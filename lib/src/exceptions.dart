/// Base class for all WebAuthn-related exceptions.
class WebAuthnException implements Exception {
  final String message;
  WebAuthnException(this.message);

  @override
  String toString() => 'WebAuthnException: $message';
}

/// Thrown when the binary `authenticatorData` is malformed or cannot be parsed.
class InvalidAuthenticatorDataException extends WebAuthnException {
  InvalidAuthenticatorDataException(super.message);
}

/// Thrown when an unsupported cryptographic algorithm or curve is encountered.
class UnsupportedAlgorithmException extends WebAuthnException {
  UnsupportedAlgorithmException(super.message);
}
