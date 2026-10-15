# AniBaka fork

Upstream: https://github.com/ech-research/ech_http

This fork preserves the upstream history and MIT license. It adds reusable
RFC 8484 DoH resolution, a per-destination ECH HTTP policy, a Dio adapter, and
Windows/Flutter toolchain compatibility fixes. It is consumed through pinned
Git commits; it is not published to pub.dev under the upstream package name.

- `DohResolver` supports A, AAAA, CNAME and HTTPS records, bounded TTL caches,
  in-flight query deduplication, response validation and total query deadlines.
- `DohResolver.connect` can be assigned to `HttpClient.connectionFactory`
  without changing HTTP Host, TLS SNI or certificate identity.
- `PrivacyHttpClient` discovers ECH for each redirect destination. Discovered
  ECH configurations require a successful encrypted handshake. Destinations
  without ECH records use the supplied HTTP client. Proxy selection is supplied
  by the application, with no dependency on Flutter or platform settings.
- `package:ech_http/dio.dart` exposes `PrivacyDioAdapter` with streaming
  request/response handling, cancellation and operation deadlines.
- The Windows CA bundle is embedded in separately appended 8,000-byte strings
  to avoid MSVC C2026; MSVC reads BoringSSL headers with `/utf-8`.
- Build-hook constraints retain compatibility with Flutter 3.44's pinned
  dependencies without dependency overrides.
- Native CMake build directories include the source location, so switching
  between hosted, path and Git dependencies does not reuse an incompatible cache.

Application settings, persistence, platform proxy discovery and app lifecycle
belong to consuming applications and are intentionally absent from this package.

Run `dart test` for offline tests. Set `ECH_TEST_DOH_LIVE=1` to include the
Cloudflare DoH/ECH trace check. Set `ECH_TEST_PROXY=http://host:port` when an
HTTP CONNECT proxy is required. Native SDK archives remain checksum-pinned.

## HTTP usage

```dart
import 'dart:io';
import 'package:ech_http/ech_http.dart';
import 'package:http/io_client.dart';

Future<void> main() async {
  // Applications may replace this callback with their own proxy selection.
  String proxyFor(Uri _) => 'DIRECT';
  final bootstrap = IOClient(HttpClient()
    ..connectionFactory = null // prevent recursive DoH in HttpOverrides hosts
    ..badCertificateCallback = null
    ..findProxy = proxyFor);
  final dns = DohResolver(
    client: bootstrap,
    endpoint: Uri.parse('https://1.1.1.1/dns-query'),
  );
  final ordinary = IOClient(HttpClient()
    ..connectionFactory = dns.connect
    ..badCertificateCallback = null
    ..findProxy = proxyFor);
  final client = PrivacyHttpClient(
    client: ordinary,
    resolver: dns,
    proxyFor: proxyFor,
  );
  try {
    final response = await client.get(
      Uri.parse('https://crypto.cloudflare.com/cdn-cgi/trace'),
    );
    print(response.body);
  } finally {
    client.close(); // closes ordinary client and native ECH transports
    dns.close(); // closes its bootstrap client
  }
}
```

For DoH without ECH, use the DoH-connected `ordinary` client directly. For Dio,
import `package:ech_http/dio.dart` and assign `PrivacyDioAdapter(client)` to
`Dio.httpClientAdapter`. `PrivacyDioAdapter.withFactory` accepts a client factory
keyed by the request's connect timeout and owns the clients it creates.

This policy covers only requests sent through these clients. It cannot change
WebView, media-player, UDP, or other applications' network stacks. Bootstrap
DoH endpoint hostnames and proxy server hostnames can still use system DNS;
an IP-literal endpoint avoids the former. Single-label and `.local` names
continue to use local resolution.
