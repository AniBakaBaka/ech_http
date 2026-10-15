import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

/// RFC 8484 wire-format DNS, including HTTPS records carrying ECHConfigList.
/// Resolver errors never fall back to the system DNS service.
class DohResolver {
  DohResolver({
    required this.client,
    required this.endpoint,
    DateTime Function()? now,
    this.timeout = const Duration(seconds: 8),
  }) : _now = now ?? DateTime.now {
    if (endpoint.scheme != 'https' ||
        endpoint.host.isEmpty ||
        endpoint.userInfo.isNotEmpty ||
        endpoint.hasFragment ||
        endpoint.queryParameters.containsKey('dns')) {
      throw ArgumentError.value(
        endpoint,
        'endpoint',
        'Expected an HTTPS DoH endpoint',
      );
    }
    if (timeout <= Duration.zero) throw ArgumentError.value(timeout, 'timeout');
  }

  final http.Client client;
  final Uri endpoint;
  final Duration timeout;
  final DateTime Function() _now;
  final _cache =
      <(String, int), ({List<DnsRecord> records, DateTime expires})>{};
  final _pending = <(String, int), Future<List<DnsRecord>>>{};
  final _random = Random.secure();
  bool _closed = false;

  void close() {
    _closed = true;
    _cache.clear();
    client.close();
  }

  /// Connection factory for dart:io HttpClient, preserving TLS host identity.
  Future<ConnectionTask<Socket>> connect(
    Uri uri,
    String? proxyHost,
    int? proxyPort,
  ) async {
    // Proxy names belong to the configured proxy route; do not rewrite them.
    if (proxyHost != null) return Socket.startConnect(proxyHost, proxyPort!);
    if (isLocal(uri.host)) {
      return Socket.startConnect(uri.host, uri.port);
    }
    final addresses = await lookup(uri.host);
    Socket? connected;
    ConnectionTask<Socket>? current;
    var cancelled = false;
    final socket = () async {
      Object? lastError;
      for (final address in addresses) {
        if (cancelled) throw const SocketException('Connection cancelled');
        try {
          current = await Socket.startConnect(address, uri.port);
          connected = await current!.socket.timeout(
            const Duration(seconds: 4),
            onTimeout: () {
              current?.cancel();
              throw const SocketException('Connection timed out');
            },
          );
          if (cancelled) {
            connected!.destroy();
            throw const SocketException('Connection cancelled');
          }
          return connected!;
        } on SocketException catch (error) {
          lastError = error;
        }
      }
      throw lastError ??
          SocketException('DoH could not connect to ${uri.host}');
    }();
    return ConnectionTask.fromSocket(socket, () {
      cancelled = true;
      current?.cancel();
      connected?.destroy();
    });
  }

  static bool isLocal(String host) {
    final name = host.toLowerCase();
    return InternetAddress.tryParse(name) != null ||
        !name.contains('.') ||
        name.endsWith('.localhost') ||
        name.endsWith('.local');
  }

  Future<List<InternetAddress>> lookup(String host) async {
    final literal = InternetAddress.tryParse(host);
    if (literal != null) return [literal];
    if (isLocal(host)) return InternetAddress.lookup(host);
    final answers = await Future.wait([query(host, 1), query(host, 28)]);
    final addresses = <InternetAddress>[];
    for (final records in answers) {
      for (final record in records) {
        if (record.type == 1 || record.type == 28) {
          addresses.add(InternetAddress.fromRawAddress(record.data));
        }
      }
    }
    if (addresses.isEmpty) {
      throw SocketException('DoH returned no addresses for $host');
    }
    return addresses;
  }

  Future<List<DnsRecord>> query(String host, int type, [int depth = 0]) async {
    if (_closed) throw StateError('DoH resolver is closed');
    if (depth > 8) throw const FormatException('DNS alias loop');
    final name = host.toLowerCase().replaceFirst(RegExp(r'\.$'), '');
    final key = (name, type);
    final cached = _cache[key];
    if (cached != null && cached.expires.isAfter(_now())) return cached.records;
    final pending = _pending[key];
    if (pending != null) return pending;
    final future = _load(name, type, depth);
    _pending[key] = future;
    try {
      return await future;
    } finally {
      if (identical(_pending[key], future)) _pending.remove(key);
    }
  }

  Future<List<DnsRecord>> _load(String host, int type, int depth) async {
    if (depth > 8) throw const FormatException('DNS alias loop');
    final id = _random.nextInt(65536);
    final query = BytesBuilder()
      ..add([id >> 8, id & 255, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for (final label in host.split('.')) {
      final bytes = ascii.encode(label);
      if (bytes.isEmpty || bytes.length > 63) {
        throw const FormatException('Invalid DNS name');
      }
      query.add([bytes.length, ...bytes]);
    }
    query.add([0, type >> 8, type & 255, 0, 1]);
    final abort = Completer<void>();
    final request = http.AbortableRequest(
      'GET',
      endpoint.replace(
        queryParameters: {
          ...endpoint.queryParameters,
          'dns': base64Url.encode(query.takeBytes()).replaceAll('=', ''),
        },
      ),
      abortTrigger: abort.future,
    )..headers['accept'] = 'application/dns-message';
    Future<({Uint8List bytes, int age})> exchange() async {
      final response = await client.send(request);
      if (response.statusCode != 200 ||
          response.headers['content-type']?.split(';').first.trim() !=
              'application/dns-message') {
        await response.stream.listen(null).cancel();
        throw http.ClientException(
          'Invalid DoH response (HTTP ${response.statusCode})',
          endpoint,
        );
      }
      final body = BytesBuilder(copy: false);
      await for (final chunk in response.stream) {
        if (body.length + chunk.length > 65535) {
          throw const FormatException('DNS response too large');
        }
        body.add(chunk);
      }
      return (
        bytes: body.takeBytes(),
        age: int.tryParse(response.headers['age'] ?? '') ?? 0,
      );
    }

    // Abort plus a wall-clock deadline also covers a stalled socket open.
    final response = await exchange().timeout(
      timeout,
      onTimeout: () {
        abort.complete();
        throw TimeoutException('DoH query timed out', timeout);
      },
    );
    final records = DnsMessage.parse(
      response.bytes,
      id: id,
      host: host,
      type: type,
    );
    var selected = records
        .where((rr) => rr.name == host && rr.type == type)
        .toList();
    var ttl = 300;
    if (selected.isEmpty) {
      final aliases = records.where((rr) => rr.name == host && rr.type == 5);
      if (aliases.isNotEmpty) {
        final alias = aliases.first;
        ttl = min(ttl, alias.ttl);
        selected = await _load(alias.target!, type, depth + 1);
      }
    }
    for (final rr in selected) {
      ttl = min(ttl, rr.ttl);
    }
    ttl = max(0, ttl - max(0, response.age));
    // Empty responses have a short negative cache, never a permanent failure.
    if (selected.isEmpty) ttl = min(ttl, 30);
    if (!_closed && ttl > 0) {
      if (_cache.length >= 256) _cache.remove(_cache.keys.first);
      _cache[(host, type)] = (
        records: List.unmodifiable(selected),
        expires: _now().add(Duration(seconds: ttl)),
      );
    }
    return selected;
  }
}

class DnsRecord {
  const DnsRecord(
    this.name,
    this.type,
    this.ttl,
    this.data, {
    this.target,
    this.priority = 0,
    this.params = const {},
  });
  final String name;
  final int type, ttl, priority;
  final Uint8List data;
  final String? target;
  final Map<int, Uint8List> params;
}

/// Bounds-checked DNS parser. Compression loops and truncated RDATA are rejected.
class DnsMessage {
  DnsMessage._(this.bytes) : view = ByteData.sublistView(bytes);
  final Uint8List bytes;
  final ByteData view;
  int offset = 0;

  int _u16() {
    _require(2);
    final value = view.getUint16(offset);
    offset += 2;
    return value;
  }

  void _require(int length) {
    if (length < 0 || offset + length > bytes.length) {
      throw const FormatException('Truncated DNS message');
    }
  }

  String _name() {
    var cursor = offset;
    var jumped = false;
    final seen = <int>{};
    final labels = <String>[];
    var length = 0;
    while (true) {
      if (cursor >= bytes.length || !seen.add(cursor)) {
        throw const FormatException('Invalid DNS compression');
      }
      final size = bytes[cursor++];
      if (size == 0) {
        if (!jumped) offset = cursor;
        return labels.join('.').toLowerCase();
      }
      if (size & 0xc0 == 0xc0) {
        if (cursor >= bytes.length) {
          throw const FormatException('Truncated DNS pointer');
        }
        final target = ((size & 63) << 8) | bytes[cursor++];
        if (!jumped) offset = cursor;
        jumped = true;
        cursor = target;
      } else {
        if (size > 63 ||
            cursor + size > bytes.length ||
            (length += size + 1) > 254) {
          throw const FormatException('Invalid DNS label');
        }
        labels.add(ascii.decode(bytes.sublist(cursor, cursor + size)));
        cursor += size;
      }
    }
  }

  static List<DnsRecord> parse(
    Uint8List bytes, {
    required int id,
    required String host,
    required int type,
  }) {
    final message = DnsMessage._(bytes);
    if (message._u16() != id) {
      throw const FormatException('DNS transaction mismatch');
    }
    final flags = message._u16();
    if (flags & 0x8000 == 0 || flags & 0x7a00 != 0 || flags & 15 != 0) {
      throw const FormatException('Unsuccessful or truncated DNS response');
    }
    final questions = message._u16();
    final count = message._u16();
    message._u16();
    message._u16();
    if (questions != 1 ||
        message._name() != host ||
        message._u16() != type ||
        message._u16() != 1) {
      throw const FormatException('DNS question mismatch');
    }
    final records = <DnsRecord>[];
    for (var i = 0; i < count; i++) {
      final name = message._name();
      final rrType = message._u16();
      final rrClass = message._u16();
      message._require(4);
      final ttl = message.view.getUint32(message.offset);
      message.offset += 4;
      final size = message._u16();
      message._require(size);
      final end = message.offset + size;
      final data = Uint8List.sublistView(bytes, message.offset, end);
      String? target;
      var priority = 0;
      final params = <int, Uint8List>{};
      if (rrType == 1 && size != 4 || rrType == 28 && size != 16) {
        throw const FormatException('Invalid DNS address');
      }
      if (rrType == 5) target = message._name();
      if (rrType == 65) {
        priority = message._u16();
        target = message._name();
        var previous = -1;
        while (message.offset < end) {
          final key = message._u16();
          final length = message._u16();
          if (key <= previous || message.offset + length > end) {
            throw const FormatException('Invalid HTTPS parameters');
          }
          previous = key;
          params[key] = Uint8List.sublistView(
            bytes,
            message.offset,
            message.offset + length,
          );
          message.offset += length;
        }
      }
      if (message.offset > end) {
        throw const FormatException('Invalid DNS RDATA');
      }
      message.offset = end;
      if (rrClass == 1) {
        records.add(
          DnsRecord(
            name,
            rrType,
            ttl,
            data,
            target: target,
            priority: priority,
            params: params,
          ),
        );
      }
    }
    return records;
  }
}
