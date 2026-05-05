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
(CborValue value, int consumed) decodeOne(Uint8List data) {
  CborValue? result;
  int consumed = 0;

  final innerSink = ChunkedConversionSink<CborValue>.withCallback((values) {
    if (values.isNotEmpty) result = values.first;
  });

  final sink = cbor.decoder.startChunkedConversion(innerSink);

  for (int i = 0; i < data.length; i++) {
    sink.add([data[i]]);
    if (result != null) {
      consumed = i + 1;
      break;
    }
  }

  if (result == null) {
    // Attempt to close the sink to see if it flushes a value
    // (some objects might only be "complete" once the stream ends)
    try {
      sink.close();
      if (result != null) {
        // If result was found only after close, it means we consumed
        // the entire input buffer.
        consumed = data.length;
      }
    } catch (_) {
      // Ignore errors during close if we already have no result
    }

    if (result == null) {
      throw InvalidAuthenticatorDataException('No valid CBOR object found');
    }
  }

  return (result!, consumed);
}
