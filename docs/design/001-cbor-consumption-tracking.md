# ADR 001: Robust CBOR Consumption Tracking

## Status
Accepted

## Context
WebAuthn uses CBOR for several variable-length data structures, most notably the `credentialPublicKey` and `extensions` within the binary `authenticatorData` blob. These fields are contiguous; to find where the `extensions` begin, we must know exactly how many bytes the `credentialPublicKey` consumed.

The `cbor` package (v6.x) provides a one-shot `cbor.decode()` API, but it does not return the number of bytes consumed. It simply decodes the first valid object and ignores the rest (or fails if the outer structure is invalid).

## Decision
We will implement a "Byte-by-Byte Chunked Decoder" utility. By using the `cbor.decoder.startChunkedConversion` API and feeding bytes one at a time, we can intercept the exact moment the internal state machine completes a full CBOR object.

The utility will reside in `lib/src/helpers/cbor_utils.dart` and provide a method:
```dart
(CborValue value, int consumed) decodeOne(Uint8List data)
```

## Consequences
- **Robustness**: We can accurately slice multiple CBOR objects packed into a single binary blob.
- **Validation**: We can detect "trailing garbage" after a payload that should be fully consumed.
- **Performance**: While byte-by-byte iteration is theoretically slower than bulk decoding, WebAuthn payloads are small (typically < 1KB), making the overhead negligible compared to the gain in correctness.
- **Maintainability**: This "clever" logic is isolated in a utility file and documented here, preventing accidental "simplification" that would break extension support.
