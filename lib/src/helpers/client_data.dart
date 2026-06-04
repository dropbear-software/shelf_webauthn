import 'dart:convert';
import 'dart:typed_data';
import 'package:collection/collection.dart';
import '../exceptions.dart';

/// The type of WebAuthn ceremony.
enum ClientDataType {
  /// "webauthn.create" - Registration ceremony.
  create('webauthn.create'),

  /// "webauthn.get" - Authentication ceremony.
  get('webauthn.get');

  final String value;
  const ClientDataType(this.value);

  /// Parses a string into a [ClientDataType].
  static ClientDataType fromString(String value) {
    return ClientDataType.values.firstWhere(
      (e) => e.value == value,
      orElse: () => throw InvalidAuthenticatorDataException(
        'Unknown clientData type: $value',
      ),
    );
  }
}

/// Represents the contextual information provided by the browser during a
/// WebAuthn ceremony.
///
/// See Section 5.8.1 of the WebAuthn specification.
class CollectedClientData {
  /// The type of ceremony.
  final ClientDataType type;

  /// The base64url-encoded challenge provided by the Relying Party.
  final String challenge;

  /// The fully qualified origin of the requester.
  final Uri origin;

  /// Whether the request was made from a cross-origin context.
  final bool? crossOrigin;

  /// The top-level origin, if available.
  final Uri? topOrigin;

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

  Uint8List? _decodedChallenge;

  /// Returns the challenge bytes, decoding them if necessary.
  Uint8List get decodedChallenge {
    if (_decodedChallenge != null) return _decodedChallenge!;

    try {
      final decoded = base64Url.decode(base64Url.normalize(challenge));
      _decodedChallenge = decoded.asUnmodifiableView();
      return _decodedChallenge!;
    } catch (e) {
      throw InvalidAuthenticatorDataException('Malformed challenge base64: $e');
    }
  }

  /// Validates the client data against the expected context.
  void verify({
    required ClientDataType expectedType,
    required List<int> expectedChallenge,
    required String expectedOrigin,
    bool allowCrossOrigin = false,
  }) {
    // 1. Verify type
    if (type != expectedType) {
      throw InvalidAuthenticatorDataException(
        'Unexpected clientData type: expected ${expectedType.value}, got ${type.value}',
      );
    }

    // 2. Verify challenge
    if (!const ListEquality().equals(decodedChallenge, expectedChallenge)) {
      throw InvalidAuthenticatorDataException('Challenge mismatch');
    }

    // 3. Verify origin
    if (origin.toString() != expectedOrigin) {
      throw InvalidAuthenticatorDataException(
        'Origin mismatch: expected $expectedOrigin, got ${origin.toString()}',
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
    if (data.length > 65536) {
      throw InvalidAuthenticatorDataException(
        'clientDataJSON exceeds maximum allowed size (64KB)',
      );
    }

    late Map<String, dynamic> map;
    try {
      final jsonString = utf8.decode(data);
      map = json.decode(jsonString) as Map<String, dynamic>;
    } catch (e) {
      throw InvalidAuthenticatorDataException(
        'Failed to parse clientDataJSON: $e',
      );
    }

    final typeStr = map['type'];
    final challenge = map['challenge'];
    final originStr = map['origin'];

    if (typeStr is! String || challenge is! String || originStr is! String) {
      throw InvalidAuthenticatorDataException(
        'Missing required fields in clientDataJSON',
      );
    }

    try {
      return CollectedClientData(
        type: ClientDataType.fromString(typeStr),
        challenge: challenge,
        origin: Uri.parse(originStr),
        crossOrigin: map['crossOrigin'] as bool?,
        topOrigin: map['topOrigin'] != null
            ? Uri.parse(map['topOrigin'] as String)
            : null,
        rawData: map,
      );
    } catch (e) {
      throw InvalidAuthenticatorDataException(
        'Invalid URI in clientDataJSON: $e',
      );
    }
  }
}
