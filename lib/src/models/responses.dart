import 'dart:typed_data';
import 'package:collection/collection.dart';

final class AuthenticatorAttestationResponse {
  /// The JSON-compatible serialization of client data (e.g., challenge, origin)
  /// passed to the authenticator by the client in order to generate this credential.
  final Uint8List clientDataJSON;

  /// The attestation object, which contains authenticator data and an attestation statement.
  final Uint8List attestationObject;

  /// A list of transports (e.g., "usb", "nfc", "ble", "internal", "hybrid")
  /// that the authenticator is believed to support, or an empty list if unknown.
  final List<String>? transports;

  const AuthenticatorAttestationResponse({
    required this.clientDataJSON,
    required this.attestationObject,
    this.transports,
  });

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is AuthenticatorAttestationResponse &&
          runtimeType == other.runtimeType &&
          const ListEquality().equals(clientDataJSON, other.clientDataJSON) &&
          const ListEquality().equals(
            attestationObject,
            other.attestationObject,
          ) &&
          const ListEquality().equals(transports, other.transports);

  @override
  int get hashCode =>
      const ListEquality().hash(clientDataJSON) ^
      const ListEquality().hash(attestationObject) ^
      const ListEquality().hash(transports);
}

final class AuthenticatorAssertionResponse {
  // TODO: Add fields for clientDataJSON, authenticatorData, signature, userHandle
  const AuthenticatorAssertionResponse();
}
