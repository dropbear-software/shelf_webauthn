import 'package:collection/collection.dart';

final class CredentialRecord {
  final String credentialId;
  final List<int> publicKey;
  final int signCount;

  const CredentialRecord({
    required this.credentialId,
    required this.publicKey,
    required this.signCount,
  });

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is CredentialRecord &&
          runtimeType == other.runtimeType &&
          credentialId == other.credentialId &&
          const ListEquality().equals(publicKey, other.publicKey) &&
          signCount == other.signCount;

  @override
  int get hashCode =>
      credentialId.hashCode ^
      const ListEquality().hash(publicKey) ^
      signCount.hashCode;
}
