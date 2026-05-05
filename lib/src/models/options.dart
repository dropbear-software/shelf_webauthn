final class PublicKeyCredentialCreationOptions {
  final String challenge;

  const PublicKeyCredentialCreationOptions({required this.challenge});

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is PublicKeyCredentialCreationOptions &&
          runtimeType == other.runtimeType &&
          challenge == other.challenge;

  @override
  int get hashCode => challenge.hashCode;
}

final class PublicKeyCredentialRequestOptions {
  final String challenge;

  const PublicKeyCredentialRequestOptions({required this.challenge});

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is PublicKeyCredentialRequestOptions &&
          runtimeType == other.runtimeType &&
          challenge == other.challenge;

  @override
  int get hashCode => challenge.hashCode;
}
