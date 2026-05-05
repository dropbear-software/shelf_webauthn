import 'dart:convert';
import 'dart:typed_data';
import '../models/models.dart';
import '../exceptions.dart';

Uint8List _decodeBase64Url(String value) {
  try {
    return base64Url.decode(base64Url.normalize(value));
  } catch (e) {
    throw WebAuthnException('Invalid base64url encoding: $value');
  }
}

/// Parses the JSON object returned by the browser's `navigator.credentials.create()` API
/// into an [AuthenticatorAttestationResponse].
///
/// The [json] argument is expected to contain a "response" key with the nested WebAuthn payload.
AuthenticatorAttestationResponse parseRegistrationResponseJson(
  Map<String, dynamic> json,
) {
  final response = json['response'];
  if (response is! Map) {
    throw WebAuthnException('Missing "response" object in JSON');
  }

  final clientDataJSON = response['clientDataJSON'] as String?;
  final attestationObject = response['attestationObject'] as String?;
  final transportsList = response['transports'] as List?;

  if (clientDataJSON == null || attestationObject == null) {
    throw WebAuthnException('Missing required fields in registration response');
  }

  return AuthenticatorAttestationResponse(
    clientDataJSON: _decodeBase64Url(clientDataJSON),
    attestationObject: _decodeBase64Url(attestationObject),
    transports: transportsList?.cast<String>(),
  );
}

/// Parses the JSON object returned by the browser's `navigator.credentials.get()` API
/// into an [AuthenticatorAssertionResponse].
///
/// The [json] argument is expected to contain a "response" key with the nested WebAuthn payload.
AuthenticatorAssertionResponse parseAuthenticationResponseJson(
  Map<String, dynamic> json,
) {
  final response = json['response'];
  if (response is! Map) {
    throw WebAuthnException('Missing "response" object in JSON');
  }

  final clientDataJSON = response['clientDataJSON'] as String?;
  final authenticatorData = response['authenticatorData'] as String?;
  final signature = response['signature'] as String?;
  final userHandle = response['userHandle'] as String?;

  if (clientDataJSON == null ||
      authenticatorData == null ||
      signature == null) {
    throw WebAuthnException(
      'Missing required fields in authentication response',
    );
  }

  return AuthenticatorAssertionResponse(
    clientDataJSON: _decodeBase64Url(clientDataJSON),
    authenticatorData: _decodeBase64Url(authenticatorData),
    signature: _decodeBase64Url(signature),
    userHandle: userHandle != null ? _decodeBase64Url(userHandle) : null,
  );
}
