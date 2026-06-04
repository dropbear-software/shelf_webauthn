import 'dart:typed_data';
import 'package:collection/collection.dart';

final class CredentialRecord {
  final String credentialType;
  final String credentialId;
  final List<int> publicKey;
  final int signCount;
  final bool uvInitialized;
  final List<String>? transports;
  final bool backupEligible;
  final bool backupState;
  final List<int> userHandle;

  // Optional contents
  final Uint8List? attestationObject;
  final Uint8List? attestationClientDataJSON;

  const CredentialRecord({
    this.credentialType = 'public-key',
    required this.credentialId,
    required this.publicKey,
    required this.signCount,
    required this.uvInitialized,
    this.transports,
    required this.backupEligible,
    required this.backupState,
    required this.userHandle,
    this.attestationObject,
    this.attestationClientDataJSON,
  });

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is CredentialRecord &&
          runtimeType == other.runtimeType &&
          credentialType == other.credentialType &&
          credentialId == other.credentialId &&
          const ListEquality().equals(publicKey, other.publicKey) &&
          signCount == other.signCount &&
          uvInitialized == other.uvInitialized &&
          const ListEquality().equals(transports, other.transports) &&
          backupEligible == other.backupEligible &&
          backupState == other.backupState &&
          const ListEquality().equals(userHandle, other.userHandle) &&
          const ListEquality().equals(
            attestationObject,
            other.attestationObject,
          ) &&
          const ListEquality().equals(
            attestationClientDataJSON,
            other.attestationClientDataJSON,
          );

  @override
  int get hashCode =>
      credentialType.hashCode ^
      credentialId.hashCode ^
      const ListEquality().hash(publicKey) ^
      signCount.hashCode ^
      uvInitialized.hashCode ^
      const ListEquality().hash(transports) ^
      backupEligible.hashCode ^
      backupState.hashCode ^
      const ListEquality().hash(userHandle) ^
      const ListEquality().hash(attestationObject) ^
      const ListEquality().hash(attestationClientDataJSON);
}
