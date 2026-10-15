import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:dio/dio.dart';
import 'package:http/http.dart' as http;

/// Dio bridge used when ECH is enabled; ordinary mode retains Dio's IO adapter.
class PrivacyDioAdapter implements HttpClientAdapter {
  PrivacyDioAdapter(http.Client client) : _client = client, _factory = null;
  PrivacyDioAdapter.withFactory(http.Client Function(Duration) factory)
    : _factory = factory,
      _client = null;
  final http.Client? _client;
  final http.Client Function(Duration)? _factory;
  final _clients = <Duration, http.Client>{};
  bool _closed = false;

  @override
  Future<ResponseBody> fetch(
    RequestOptions options,
    Stream<Uint8List>? requestStream,
    Future<void>? cancelFuture,
  ) async {
    if (_closed) throw StateError('HTTP adapter is closed');
    final configuredTimeout = options.connectTimeout;
    final connectTimeout =
        configuredTimeout == null || configuredTimeout == Duration.zero
        ? const Duration(seconds: 15)
        : configuredTimeout;
    final client =
        _client ??
        _clients.putIfAbsent(connectTimeout, () => _factory!(connectTimeout));
    final abort = Completer<void>();
    void cancel() {
      if (!abort.isCompleted) abort.complete();
    }

    if (cancelFuture != null) unawaited(cancelFuture.then((_) => cancel()));
    final request =
        http.AbortableStreamedRequest(
            options.method,
            options.uri,
            abortTrigger: abort.future,
          )
          ..followRedirects = options.followRedirects
          ..maxRedirects = options.maxRedirects
          ..persistentConnection = options.persistentConnection;
    for (final entry in options.headers.entries) {
      if (entry.value != null) {
        request.headers[entry.key] = entry.value is List
            ? (entry.value as List).join(', ')
            : '${entry.value}';
      }
    }
    final length = request.headers[HttpHeaders.contentLengthHeader];
    if (length != null) request.contentLength = int.parse(length);
    try {
      final sending = client.send(request);
      Future<void> upload() async {
        try {
          if (requestStream != null) {
            await request.sink.addStream(requestStream);
          }
          await request.sink.close();
        } catch (_) {
          cancel();
          rethrow;
        }
      }

      var uploading = upload();
      final sendTimeout = options.sendTimeout;
      if (sendTimeout != null && sendTimeout > Duration.zero) {
        uploading = uploading.timeout(
          sendTimeout,
          onTimeout: () {
            cancel();
            throw DioException.sendTimeout(
              timeout: sendTimeout,
              requestOptions: options,
            );
          },
        );
      }
      // Observe both futures immediately, including early connection failures.
      var responseFuture = Future.wait<Object?>(
        [sending, uploading],
        eagerError: true,
      ).then((values) => values.first as http.StreamedResponse);
      final timeout = options.receiveTimeout;
      if (timeout != null && timeout > Duration.zero) {
        responseFuture = responseFuture.timeout(
          timeout,
          onTimeout: () {
            cancel();
            throw DioException.receiveTimeout(
              timeout: timeout,
              requestOptions: options,
            );
          },
        );
      }
      final response = await responseFuture;
      var stream = response.stream.map(
        (bytes) => bytes is Uint8List ? bytes : Uint8List.fromList(bytes),
      );
      if (timeout != null && timeout > Duration.zero) {
        stream = stream.timeout(
          timeout,
          onTimeout: (sink) {
            cancel();
            sink.addError(
              DioException.receiveTimeout(
                timeout: timeout,
                requestOptions: options,
              ),
            );
            sink.close();
          },
        );
      }
      return ResponseBody(
        stream,
        response.statusCode,
        headers: response.headersSplitValues,
        statusMessage: response.reasonPhrase,
        isRedirect: response.isRedirect || response.request?.url != options.uri,
        onClose: cancel,
      );
    } on TimeoutException catch (error) {
      cancel();
      throw DioException.connectionTimeout(
        requestOptions: options,
        timeout: connectTimeout,
        error: error,
      );
    } on http.RequestAbortedException catch (error) {
      cancel();
      throw DioException(
        requestOptions: options,
        type: DioExceptionType.cancel,
        error: error,
      );
    } on http.ClientException catch (error) {
      cancel();
      throw DioException.connectionError(
        requestOptions: options,
        reason: error.message,
        error: error,
      );
    } catch (_) {
      cancel();
      rethrow;
    }
  }

  @override
  void close({bool force = false}) {
    _closed = true;
    _client?.close();
    for (final client in _clients.values) {
      client.close();
    }
    _clients.clear();
  }
}
