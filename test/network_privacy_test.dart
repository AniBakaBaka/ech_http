import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dio/dio.dart';
import 'package:ech_http/ech_http.dart';
import 'package:test/test.dart';
import 'package:ech_http/dio.dart';
import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';
import 'package:http/testing.dart';

void main() {
  test('DoH uses wire messages, deduplicates queries and honors TTL', () async {
    var calls = 0;
    var now = DateTime.utc(2026);
    final resolver = DohResolver(
      endpoint: Uri.parse('https://1.1.1.1/dns-query'),
      now: () => now,
      client: MockClient((request) async {
        calls++;
        expect(request.headers['accept'], 'application/dns-message');
        return _dnsResponse(request, type: 1, data: [203, 0, 113, 4], ttl: 2);
      }),
    );
    addTearDown(resolver.close);
    final results = await Future.wait([
      resolver.query('example.test', 1),
      resolver.query('example.test', 1),
    ]);
    expect(calls, 1);
    expect(results.first.single.data, [203, 0, 113, 4]);
    now = now.add(const Duration(seconds: 1));
    await resolver.query('example.test', 1);
    expect(calls, 1);
    now = now.add(const Duration(seconds: 1));
    await resolver.query('example.test', 1);
    expect(calls, 2);
  });

  test(
    'DoH resolves CNAME chains and rejects cycles and malformed messages',
    () async {
      var cycle = false;
      final resolver = DohResolver(
        endpoint: Uri.parse('https://1.1.1.1/dns-query'),
        client: MockClient((request) async {
          final query = _query(request);
          final name = _queryName(query);
          if (name == 'example.test' || cycle) {
            return _dnsResponse(
              request,
              type: 5,
              data: _name(
                name == 'example.test' ? 'alias.test' : 'example.test',
              ),
              ttl: 0,
            );
          }
          return _dnsResponse(request, type: 1, data: [203, 0, 113, 7], ttl: 0);
        }),
      );
      addTearDown(resolver.close);
      expect((await resolver.query('example.test', 1)).single.data, [
        203,
        0,
        113,
        7,
      ]);
      cycle = true;
      await expectLater(
        resolver.query('example.test', 1),
        throwsFormatException,
      );
      final request = http.Request(
        'GET',
        Uri.parse(
          'https://dns.test?dns=${base64Url.encode([0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, ..._name('example.test'), 0, 1, 0, 1])}',
        ),
      );
      final valid = _dnsResponse(
        request,
        type: 1,
        data: [203, 0, 113, 4],
      ).bodyBytes;
      for (final bytes in [
        valid.sublist(0, valid.length - 1),
        [...valid]..[0] = 1,
        [...valid]..[3] = 2,
        [...valid]
          ..[12] = 0xc0
          ..[13] = 12,
      ]) {
        expect(
          () => DnsMessage.parse(
            Uint8List.fromList(bytes),
            id: 1,
            host: 'example.test',
            type: 1,
          ),
          throwsFormatException,
        );
      }
    },
  );

  test('DoH failure is propagated and not cached as an empty answer', () async {
    var attempts = 0;
    final resolver = DohResolver(
      endpoint: Uri.parse('https://1.1.1.1/dns-query'),
      client: MockClient((request) async {
        if (++attempts == 1) return http.Response('unavailable', 503);
        return _dnsResponse(request, type: 1, data: [203, 0, 113, 5]);
      }),
    );
    addTearDown(resolver.close);
    await expectLater(
      resolver.query('example.test', 1),
      throwsA(isA<http.ClientException>()),
    );
    expect((await resolver.query('example.test', 1)).single.data, [
      203,
      0,
      113,
      5,
    ]);
  });

  test(
    'DoH deadline completes even if the transport ignores abortion',
    () async {
      final pending = Completer<http.StreamedResponse>();
      final aborted = Completer<void>();
      final resolver = DohResolver(
        client: _PendingClient((request) {
          (request as http.Abortable).abortTrigger!.then(
            (_) => aborted.complete(),
          );
          return pending.future;
        }),
        endpoint: Uri.parse('https://1.1.1.1/dns-query'),
        timeout: const Duration(milliseconds: 10),
      );
      addTearDown(resolver.close);
      await expectLater(
        resolver.query('example.test', 1),
        throwsA(isA<TimeoutException>()),
      );
      await aborted.future;
      pending.complete(
        http.StreamedResponse(
          Stream.value([]),
          200,
          headers: {'content-type': 'application/dns-message'},
        ),
      );
    },
  );

  test(
    'ECH preserves URL identity, uses encrypted addresses and keeps proxy routing',
    () async {
      final dns = _FakeDns();
      var nativeCalls = 0;
      final client = PrivacyHttpClient(
        client: MockClient(
          (_) async => throw StateError('Unexpected cleartext fallback'),
        ),
        resolver: dns,
        proxyFor: (_) => 'PROXY localhost:7890; DIRECT',
        echClientFactory: (route, proxy) {
          expect(route.addresses, ['203.0.113.8']);
          expect(proxy.toString(), 'http://localhost:7890');
          return MockClient((request) async {
            nativeCalls++;
            expect(request.url.host, 'secure.test');
            expect(request.headers['authorization'], 'Bearer example');
            return http.Response('encrypted', 200);
          });
        },
      );
      addTearDown(client.close);
      expect(
        (await client.get(
          Uri.parse('https://secure.test/path'),
          headers: {'authorization': 'Bearer example'},
        )).body,
        'encrypted',
      );
      expect(nativeCalls, 1);
      expect(dns.lookups, ['secure.test']);
    },
  );

  test('ECH rejection never retries with ordinary TLS', () async {
    var ordinaryCalls = 0;
    final client = PrivacyHttpClient(
      client: MockClient((_) async {
        ordinaryCalls++;
        return http.Response('unsafe', 200);
      }),
      resolver: _FakeDns(),
      proxyFor: (_) => 'DIRECT',
      echClientFactory: (_, _) =>
          MockClient((_) async => throw EchException('ECH rejected')),
    );
    addTearDown(client.close);
    await expectLater(
      client.get(Uri.parse('https://secure.test')),
      throwsA(isA<EchException>()),
    );
    expect(ordinaryCalls, 0);
  });

  test(
    'redirect destinations get their own policy and lose origin credentials',
    () async {
      final dns = _FakeDns();
      var ordinaryCalls = 0;
      final client = PrivacyHttpClient(
        client: MockClient((request) async {
          ordinaryCalls++;
          expect(request.url.host, 'plain.test');
          expect(request.headers['authorization'], isNull);
          expect(request.headers['cookie'], isNull);
          return http.Response('ok', 200);
        }),
        resolver: dns,
        proxyFor: (_) => 'DIRECT',
        echClientFactory: (_, _) => MockClient(
          (_) async => http.Response(
            '',
            302,
            headers: {'location': 'https://plain.test/next'},
          ),
        ),
      );
      addTearDown(client.close);
      expect(
        (await client.get(
          Uri.parse('https://secure.test'),
          headers: {'authorization': 'secret', 'cookie': 'session=x'},
        )).body,
        'ok',
      );
      expect(ordinaryCalls, 1);
      expect(dns.queries, ['secure.test', 'plain.test']);
    },
  );

  test(
    'cancellation interrupts ECH discovery before opening a connection',
    () async {
      final dns = _FakeDns()..pending = Completer<List<DnsRecord>>();
      final abort = Completer<void>();
      var sends = 0;
      final client = PrivacyHttpClient(
        client: MockClient((_) async {
          sends++;
          return http.Response('unexpected', 200);
        }),
        resolver: dns,
        proxyFor: (_) => 'DIRECT',
      );
      addTearDown(client.close);
      final result = client.send(
        http.AbortableRequest(
          'GET',
          Uri.parse('https://secure.test'),
          abortTrigger: abort.future,
        ),
      );
      final assertion = expectLater(
        result,
        throwsA(isA<http.RequestAbortedException>()),
      );
      abort.complete();
      await assertion;
      dns.pending!.complete([]);
      expect(sends, 0);
    },
  );

  test(
    'Dio bridge streams request bodies and preserves Set-Cookie values',
    () async {
      final client = PrivacyHttpClient(
        client: MockClient((request) async {
          expect(request.body, 'payload');
          return http.Response(
            'ok',
            200,
            headers: {
              'set-cookie':
                  'a=1; Expires=Wed, 21 Oct 2030 07:28:00 GMT,b=2; Path=/',
            },
          );
        }),
        resolver: null,
        proxyFor: (_) => 'DIRECT',
      );
      final dio = Dio()..httpClientAdapter = PrivacyDioAdapter(client);
      addTearDown(dio.close);
      final response = await dio.post<String>(
        'https://plain.test',
        data: 'payload',
      );
      expect(response.data, 'ok');
      expect(response.headers['set-cookie'], hasLength(2));
    },
  );

  test(
    'Dio bridge reports early DNS failures without waiting for upload',
    () async {
      final client = PrivacyHttpClient(
        client: MockClient((_) async => http.Response('unexpected', 200)),
        resolver: _FakeDns()..failure = const SocketException('DNS failed'),
        proxyFor: (_) => 'DIRECT',
      );
      final dio = Dio()..httpClientAdapter = PrivacyDioAdapter(client);
      addTearDown(dio.close);
      await expectLater(
        dio
            .post<String>('https://secure.test', data: 'payload')
            .timeout(const Duration(seconds: 2)),
        throwsA(isA<DioException>()),
      );
    },
  );

  test(
    'live DoH and verified native ECH handshake',
    () async {
      final previous = HttpOverrides.current;
      HttpOverrides.global = null;
      addTearDown(() => HttpOverrides.global = previous);
      final bootstrap = IOClient(
        (HttpClient()..findProxy = _liveProxy)..badCertificateCallback = null,
      );
      final dns = DohResolver(
        client: bootstrap,
        endpoint: Uri.parse('https://1.1.1.1/dns-query'),
      );
      addTearDown(dns.close);
      var encrypted = false;
      final client = PrivacyHttpClient(
        client: IOClient((HttpClient()..findProxy = _liveProxy)),
        resolver: dns,
        proxyFor: _liveProxy,
        echClientFactory: (route, proxy) => _VerifiedClient(
          EchClient(
            resolver: StaticEchResolver({'crypto.cloudflare.com': route}),
            proxy: proxy,
          ),
          () => encrypted = true,
        ),
      );
      addTearDown(client.close);
      final response = await client.get(
        Uri.parse('https://crypto.cloudflare.com/cdn-cgi/trace'),
      );
      expect(response.statusCode, 200);
      expect(encrypted, isTrue);
      expect(response.body, contains('sni=encrypted'));
    },
    skip: Platform.environment['ECH_TEST_DOH_LIVE'] != '1',
    timeout: const Timeout(Duration(seconds: 60)),
  );
}

class _VerifiedClient extends http.BaseClient {
  _VerifiedClient(this.client, this.onEncrypted);
  final EchClient client;
  final void Function() onEncrypted;
  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    final response = await client.send(request);
    if (response.echAccepted) onEncrypted();
    return response;
  }

  @override
  void close() => client.close();
}

class _FakeDns extends DohResolver {
  _FakeDns()
    : super(
        client: MockClient((_) async => throw StateError('No network')),
        endpoint: Uri.parse('https://1.1.1.1/dns-query'),
      );
  final queries = <String>[];
  final lookups = <String>[];
  Object? failure;
  Completer<List<DnsRecord>>? pending;
  List<InternetAddress> addresses = [InternetAddress('203.0.113.8')];
  @override
  Future<List<DnsRecord>> query(String host, int type, [int depth = 0]) async {
    queries.add(host);
    if (failure != null) throw failure!;
    if (pending != null) return pending!.future;
    if (host != 'secure.test' && host != 'crypto.cloudflare.com') return [];
    return [
      DnsRecord(
        host,
        65,
        60,
        Uint8List(0),
        target: '',
        priority: 1,
        params: {
          5: Uint8List.fromList([0, 4, 0xfe, 0x0d, 0, 0]),
        },
      ),
    ];
  }

  @override
  Future<List<InternetAddress>> lookup(String host) async {
    lookups.add(host);
    return addresses;
  }
}

class _PendingClient extends http.BaseClient {
  _PendingClient(this.handle);
  final Future<http.StreamedResponse> Function(http.BaseRequest) handle;
  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) =>
      handle(request);
}

Uint8List _query(http.Request request) =>
    base64Url.decode(base64Url.normalize(request.url.queryParameters['dns']!));
String _queryName(Uint8List query) {
  var offset = 12;
  final labels = <String>[];
  while (query[offset] != 0) {
    final length = query[offset++];
    labels.add(ascii.decode(query.sublist(offset, offset + length)));
    offset += length;
  }
  return labels.join('.');
}

List<int> _name(String name) => [
  for (final label in name.split('.')) ...[
    label.length,
    ...ascii.encode(label),
  ],
  0,
];
http.Response _dnsResponse(
  http.Request request, {
  required int type,
  required List<int> data,
  int ttl = 60,
}) {
  final query = _query(request);
  return http.Response.bytes(
    [
      query[0],
      query[1],
      0x81,
      0x80,
      0,
      1,
      0,
      1,
      0,
      0,
      0,
      0,
      ...query.sublist(12),
      0xc0,
      12,
      type >> 8,
      type & 255,
      0,
      1,
      ttl >> 24,
      (ttl >> 16) & 255,
      (ttl >> 8) & 255,
      ttl & 255,
      data.length >> 8,
      data.length & 255,
      ...data,
    ],
    200,
    headers: {'content-type': 'application/dns-message'},
  );
}

String _liveProxy(Uri _) {
  final proxy = Platform.environment['ECH_TEST_PROXY'];
  return proxy == null || proxy.trim().isEmpty
      ? 'DIRECT'
      : 'PROXY ${Uri.parse(proxy).authority}';
}
