import 'dart:convert';
import 'dart:typed_data';
import 'package:cbor/cbor.dart';
import '../exceptions.dart';

/// Decodes exactly one CBOR object from [data] and returns it along with
/// the number of bytes consumed.
///
/// This is necessary because the standard `cbor.decode()` does not return
/// consumption counts, which are required for parsing contiguous variable-length
/// fields in WebAuthn (e.g., Public Key followed by Extensions).
///
/// ### Optimization Strategy
/// To avoid slow, heap-allocation-heavy byte-by-byte decoding, this function:
/// 1. Processes bytes in chunks of 16 using bulk decode sink operations.
/// 2. Once a chunk triggers a completed decode, resets the sink and runs a precise,
///    byte-by-byte lookahead over only the final chunk boundary to find the exact
///    consumption offset.
/// 3. Falls back to complete byte-by-byte decoding on CBOR parsing errors to ensure
///    precise syntax exception reporting.
({CborValue value, int consumed}) decodeOne(Uint8List data) {
  const int chunkSize = 16;

  // Helper to run decoding precisely up to maxBytes byte-by-byte
  ({CborValue? value, int consumed}) tryDecode(int maxBytes) {
    CborValue? result;
    final innerSink = ChunkedConversionSink<CborValue>.withCallback((values) {
      if (values.isNotEmpty) result = values.first;
    });
    final sink = cbor.decoder.startChunkedConversion(innerSink);

    for (int i = 0; i < maxBytes; i++) {
      try {
        sink.add([data[i]]);
      } catch (e) {
        throw InvalidAuthenticatorDataException('Malformed CBOR: $e');
      }
      if (result != null) {
        return (value: result, consumed: i + 1);
      }
    }

    try {
      sink.close();
    } catch (_) {}

    return (value: result, consumed: maxBytes);
  }

  CborValue? chunkResult;
  int chunkStart = 0;

  final innerSink = ChunkedConversionSink<CborValue>.withCallback((values) {
    if (values.isNotEmpty) chunkResult = values.first;
  });
  var sink = cbor.decoder.startChunkedConversion(innerSink);

  // Phase 1: Fast scan using chunked additions
  while (chunkStart < data.length && chunkResult == null) {
    int chunkEnd = chunkStart + chunkSize;
    if (chunkEnd > data.length) chunkEnd = data.length;

    final chunk = data.sublist(chunkStart, chunkEnd);
    try {
      sink.add(chunk);
    } catch (e) {
      // In case of syntax or malformed errors, fall back to precise pass
      // for exact exception location and reporting.
      final fallback = tryDecode(data.length);
      if (fallback.value != null) {
        return (value: fallback.value!, consumed: fallback.consumed);
      }
      throw InvalidAuthenticatorDataException('Malformed CBOR: $e');
    }

    if (chunkResult != null) {
      // Phase 2: Precise scan on final chunk boundary
      final precise = tryDecode(chunkEnd);
      if (precise.value != null) {
        return (value: precise.value!, consumed: precise.consumed);
      }
    }

    chunkStart = chunkEnd;
  }

  try {
    sink.close();
  } catch (_) {}

  // Double check if EOF close triggers completion
  if (chunkResult != null) {
    final precise = tryDecode(data.length);
    if (precise.value != null) {
      return (value: precise.value!, consumed: precise.consumed);
    }
  }

  throw InvalidAuthenticatorDataException('No valid CBOR object found');
}
