import 'dart:convert';
import 'dart:typed_data';
import 'package:collection/collection.dart';
import '../exceptions.dart';

/// Represents the contextual information provided by the browser during a
/// WebAuthn ceremony.
///
/// See Section 5.8.1 of the WebAuthn specification.
class CollectedClientData {
  /// The type of ceremony. Either "webauthn.create" or "webauthn.get".
  final String type;

  /// The base64url-encoded challenge provided by the Relying Party.
  final String challenge;

  /// The fully qualified origin of the requester.
  final String origin;

  /// Whether the request was made from a cross-origin context.
  final bool? crossOrigin;

  /// The top-level origin, if available.
  final String? topOrigin;

  /// The raw JSON map, including any unknown fields for future-proofing.
  final Map<String, dynamic> rawData;

  CollectedClientData({
    required this.type,
    required this.challenge,
    required this.origin,
    this.crossOrigin,
    this.topOrigin,
    required Map<String, dynamic> rawData,
  }) : rawData = UnmodifiableMapView(rawData);

  /// Decoded challenge bytes.
  Uint8List? _decodedChallenge;

  /// Returns the challenge bytes, decoding them if necessary.
  Uint8List get decodedChallenge {
    if (_decodedChallenge != null) return _decodedChallenge!;

    // Normalize base64url by adding required padding
    String normalized = challenge;
    switch (normalized.length % 4) {
      case 2:
        normalized += '==';
      case 3:
        normalized += '=';
    }

    try {
      _decodedChallenge = base64Url.decode(normalized);
      return _decodedChallenge!;
    } catch (e) {
      throw InvalidAuthenticatorDataException('Malformed challenge base64: $e');
    }
  }

  /// Validates the client data against the expected context.
  void verify({
    required String expectedType,
    required List<int> expectedChallenge,
    required String expectedOrigin,
    bool allowCrossOrigin = false,
  }) {
    // 1. Verify type
    if (type != expectedType) {
      throw InvalidAuthenticatorDataException(
        'Unexpected clientData type: expected $expectedType, got $type',
      );
    }

    // 2. Verify challenge
    if (!const ListEquality().equals(decodedChallenge, expectedChallenge)) {
      throw InvalidAuthenticatorDataException('Challenge mismatch');
    }

    // 3. Verify origin
    if (origin != expectedOrigin) {
      throw InvalidAuthenticatorDataException(
        'Origin mismatch: expected $expectedOrigin, got $origin',
      );
    }

    // 4. Verify crossOrigin
    if (!allowCrossOrigin && crossOrigin == true) {
      throw InvalidAuthenticatorDataException(
        'Cross-origin request not allowed',
      );
    }
  }

  /// Parses the raw binary `clientDataJSON`.
  static CollectedClientData parse(Uint8List data) {
    late Map<String, dynamic> map;
    try {
      final jsonString = utf8.decode(data);
      map = json.decode(jsonString) as Map<String, dynamic>;
    } catch (e) {
      throw InvalidAuthenticatorDataException(
        'Failed to parse clientDataJSON: $e',
      );
    }

    final type = map['type'];
    final challenge = map['challenge'];
    final origin = map['origin'];

    if (type is! String || challenge is! String || origin is! String) {
      throw InvalidAuthenticatorDataException(
        'Missing required fields in clientDataJSON',
      );
    }

    return CollectedClientData(
      type: type,
      challenge: challenge,
      origin: origin,
      crossOrigin: map['crossOrigin'] as bool?,
      topOrigin: map['topOrigin'] as String?,
      rawData: map,
    );
  }
}
