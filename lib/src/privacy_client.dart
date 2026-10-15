import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

import 'client.dart';
import 'doh_resolver.dart';
import 'types.dart';

typedef EchClientFactory = http.Client Function(EchRoute route, Uri? proxy);

/// Chooses ECH per redirect destination. Hosts without HTTPS/ECH records still
/// use the DoH-enabled IO client; discovery/handshake failures are propagated.
class PrivacyHttpClient extends http.BaseClient {
  PrivacyHttpClient({
    required this.client,
    required this.resolver,
    required this.proxyFor,
    this.connectTimeout = const Duration(seconds: 15),
    EchClientFactory? echClientFactory,
  }) : _echClientFactory =
           echClientFactory ??
           ((route, proxy) => _nativeClient(route, proxy, connectTimeout));

  final http.Client client;
  final DohResolver? resolver;
  final String Function(Uri) proxyFor;
  final Duration connectTimeout;
  final EchClientFactory _echClientFactory;
  final _nativeClients = <http.Client>{};
  final _closed = Completer<void>();

  static http.Client _nativeClient(
    EchRoute route,
    Uri? proxy,
    Duration connectTimeout,
  ) => EchClient(
    resolver: _FixedEchResolver(route),
    proxy: proxy,
    // Dio and the shared API sender enforce their own per-operation deadlines.
    timeout: const Duration(days: 1),
    connectTimeout: connectTimeout,
    maxResponseBytes: 1 << 50,
  );

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    final abort = request is http.Abortable ? request.abortTrigger : null;
    Future<T> race<T>(Future<T> future) => Future.any([
      future,
      _closed.future.then<T>(
        (_) => throw http.ClientException('Client is closed', request.url),
      ),
      if (abort != null)
        abort.then<T>((_) => throw http.RequestAbortedException(request.url)),
    ]);
    if (_closed.isCompleted) {
      throw http.ClientException('Client is closed', request.url);
    }
    var current = request;
    var redirects = 0;
    while (true) {
      if (current.url.scheme != 'http' && current.url.scheme != 'https') {
        throw http.ClientException(
          'Only HTTP(S) URLs are supported',
          current.url,
        );
      }
      final route =
          resolver == null ||
              current.url.scheme != 'https' ||
              DohResolver.isLocal(current.url.host)
          ? null
          : await race(_route(current.url).timeout(connectTimeout));
      http.Client? native;
      if (route != null) {
        final directive = proxyFor(current.url).split(';').first.trim();
        Uri? proxy;
        if (directive != 'DIRECT') {
          if (!directive.startsWith('PROXY ')) {
            throw http.ClientException(
              'ECH requires an HTTP CONNECT proxy',
              current.url,
            );
          }
          proxy = Uri.parse('http://${directive.substring(6).trim()}');
        }
        native = _echClientFactory(route, proxy);
        _nativeClients.add(native);
      }
      final outgoing = _ForwardRequest(
        current,
        abortTrigger: abort == null
            ? _closed.future
            : Future.any([abort, _closed.future]),
      );
      http.StreamedResponse response;
      try {
        response = await (native ?? client).send(outgoing);
      } catch (_) {
        if (native != null) {
          _nativeClients.remove(native);
          native.close();
        }
        rethrow;
      }
      void release() {
        if (native != null) {
          _nativeClients.remove(native);
          native.close();
        }
      }

      final location = response.headers['location'];
      final status = response.statusCode;
      final redirect =
          location != null &&
          request.followRedirects &&
          ((const [301, 302, 303, 307, 308].contains(status) &&
                  (current.method == 'GET' || current.method == 'HEAD')) ||
              (status == 303 && current.method == 'POST'));
      if (!redirect) {
        return http.StreamedResponse(
          _releaseStream(response.stream, release),
          response.statusCode,
          contentLength: response.contentLength,
          headers: response.headers,
          isRedirect: response.isRedirect,
          reasonPhrase: response.reasonPhrase,
          request: current,
        );
      }
      await response.stream.listen(null).cancel();
      release();
      if (++redirects > request.maxRedirects) {
        throw http.ClientException('Too many redirects', request.url);
      }
      final next = current.url.resolve(location);
      if (current.url.scheme == 'https' && next.scheme != 'https') {
        throw http.ClientException('HTTPS redirect downgrade refused', next);
      }
      final headers = Map<String, String>.of(current.headers);
      if (next.origin != current.url.origin) {
        headers.removeWhere(
          (key, _) => const {
            'authorization',
            'cookie',
            'host',
            'origin',
            'referer',
            'proxy-authorization',
          }.contains(key.toLowerCase()),
        );
      }
      headers.removeWhere(
        (key, _) => const {
          'content-length',
          'content-type',
          'transfer-encoding',
        }.contains(key.toLowerCase()),
      );
      current =
          http.Request(
              status == 303 && current.method != 'HEAD'
                  ? 'GET'
                  : current.method,
              next,
            )
            ..headers.addAll(headers)
            ..persistentConnection = request.persistentConnection;
    }
  }

  Future<EchRoute?> _route(Uri uri) async {
    var host = uri.host;
    var records = await resolver!.query(
      uri.port == 443 ? host : '_${uri.port}._https.$host',
      65,
    );
    for (var hop = 0; ; hop++) {
      final aliases = records.where(
        (rr) => rr.priority == 0 && rr.target!.isNotEmpty,
      );
      if (aliases.isEmpty) break;
      if (hop == 7) throw const FormatException('HTTPS alias loop');
      host = aliases.first.target!;
      records = await resolver!.query(host, 65);
    }
    records = records.toList()
      ..sort((a, b) => a.priority.compareTo(b.priority));
    for (final record in records) {
      if (record.priority == 0 || !record.params.containsKey(5)) continue;
      final mandatory = record.params[0];
      if (mandatory != null) {
        if (mandatory.length.isOdd) {
          throw const FormatException('Invalid HTTPS mandatory keys');
        }
        final keys = ByteData.sublistView(mandatory);
        if ([
          for (var i = 0; i < mandatory.length; i += 2) keys.getUint16(i),
        ].any(
          (key) =>
              !const {0, 3, 4, 5, 6}.contains(key) ||
              !record.params.containsKey(key),
        )) {
          continue;
        }
      }
      final port = record.params[3];
      if (port != null &&
          (port.length != 2 ||
              ByteData.sublistView(port).getUint16(0) != uri.port)) {
        continue;
      }
      // Address lookups remain encrypted, including when HTTPS records lack hints.
      final addresses = await resolver!.lookup(
        record.target!.isEmpty ? host : record.target!,
      );
      return EchRoute(
        configList: base64.encode(record.params[5]!),
        addresses: addresses.map((ip) => ip.address).toList(),
      );
    }
    return null;
  }

  static Stream<List<int>> _releaseStream(
    Stream<List<int>> stream,
    void Function() release,
  ) async* {
    try {
      yield* stream;
    } finally {
      release();
    }
  }

  @override
  void close() {
    if (_closed.isCompleted) return;
    _closed.complete();
    client.close();
    for (final native in _nativeClients) {
      native.close();
    }
    _nativeClients.clear();
  }
}

class _FixedEchResolver implements EchResolver {
  const _FixedEchResolver(this.route);
  final EchRoute route;
  @override
  Future<EchRoute?> resolve(Uri uri) async => route;
}

class _ForwardRequest extends http.BaseRequest with http.Abortable {
  _ForwardRequest(this.source, {required this.abortTrigger})
    : super(source.method, source.url) {
    headers.addAll(source.headers);
    contentLength = source.contentLength;
    followRedirects = false;
    persistentConnection = source.persistentConnection;
  }
  final http.BaseRequest source;
  @override
  final Future<void> abortTrigger;
  @override
  http.ByteStream finalize() {
    super.finalize();
    return source.finalize();
  }
}
