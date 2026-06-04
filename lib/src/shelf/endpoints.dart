import 'dart:convert';
import 'package:shelf/shelf.dart';
import 'package:shelf_router/shelf_router.dart';
import '../shelf_webauthn_base.dart';
import '../models/models.dart';
import '../exceptions.dart';
import 'parsers.dart';

/// An interface for storing and retrieving temporary WebAuthn challenges.
abstract class WebAuthnChallengeStore {
  /// Save a cryptographic challenge for the duration of a ceremony.
  ///
  /// The [sessionId] is an opaque identifier for the current user's session.
  Future<void> saveChallenge(String sessionId, String challenge);

  /// Retrieve and consume (delete) a challenge.
  ///
  /// Must return null if no challenge exists or if it has expired.
  Future<String?> getAndConsumeChallenge(String sessionId);
}

/// An interface for storing and retrieving user credentials.
abstract class WebAuthnCredentialStore {
  /// Save a newly registered credential.
  Future<void> saveCredential(String userId, CredentialRecord credential);

  /// Retrieve a credential by its unique ID.
  Future<CredentialRecord?> getCredential(String credentialId);

  /// Check if a credential ID is already registered.
  Future<bool> isCredentialIdRegistered(String credentialId);
}

/// A pre-built [Router] for standard WebAuthn flows.
class WebAuthnEndpoints {
  /// The core WebAuthn server logic instance.
  final WebAuthnServer server;

  /// The datastore for temporary cryptographic challenges.
  final WebAuthnChallengeStore challengeStore;

  /// The datastore for registered user credentials.
  final WebAuthnCredentialStore credentialStore;

  /// A callback to extract a session ID from a request (e.g. from a cookie or header).
  final String Function(Request request) getSessionId;

  /// A callback to extract a user ID from a request.
  final String Function(Request request) getUserId;

  /// An optional callback to supply allowed credentials during authentication.
  final Future<List<PublicKeyCredentialDescriptor>> Function(
    Request request,
    Map<String, dynamic> body,
  )?
  getAllowCredentials;

  WebAuthnEndpoints({
    required this.server,
    required this.challengeStore,
    required this.credentialStore,
    required this.getSessionId,
    required this.getUserId,
    this.getAllowCredentials,
  });

  Response _jsonResponse(Map<String, dynamic> json, {int status = 200}) {
    return Response(
      status,
      body: jsonEncode(json),
      headers: {'content-type': 'application/json'},
    );
  }

  Response _errorResponse(Object error) {
    if (error is WebAuthnException) {
      return Response.badRequest(
        body: jsonEncode({'error': error.message}),
        headers: {'content-type': 'application/json'},
      );
    }
    return Response.internalServerError(
      body: jsonEncode({'error': 'Internal server error: $error'}),
      headers: {'content-type': 'application/json'},
    );
  }

  Response _errorJson(String message, {int status = 400}) {
    return Response(
      status,
      body: jsonEncode({'error': message}),
      headers: {'content-type': 'application/json'},
    );
  }

  Future<Map<String, dynamic>> _readJson(Request request) async {
    final body = await request.readAsString();
    if (body.isEmpty) return <String, dynamic>{};
    try {
      final decoded = jsonDecode(body);
      if (decoded is! Map) {
        throw WebAuthnException('JSON body must be a map');
      }
      return decoded.cast<String, dynamic>();
    } catch (e) {
      if (e is WebAuthnException) rethrow;
      throw WebAuthnException('Malformed JSON body: $e');
    }
  }

  /// Returns a configured [Router] with the standard 4 WebAuthn endpoints:
  ///
  /// - POST `/register/options`
  /// - POST `/register/verify`
  /// - POST `/authenticate/options`
  /// - POST `/authenticate/verify`
  Router get router {
    final r = Router();

    // 1. Generate Registration Options
    r.post('/register/options', (Request request) async {
      try {
        final sessionId = getSessionId(request);
        final userId = getUserId(request);

        final json = await _readJson(request);

        final username = json['username'] as String?;
        if (username == null) {
          return _errorJson('Missing username');
        }

        AuthenticatorSelectionCriteria? authenticatorSelection;
        if (json['authenticatorSelection'] is Map) {
          final sel = json['authenticatorSelection'] as Map<String, dynamic>;
          authenticatorSelection = AuthenticatorSelectionCriteria(
            authenticatorAttachment: sel['authenticatorAttachment'] as String?,
            requireResidentKey: sel['requireResidentKey'] as bool?,
            residentKey: sel['residentKey'] as String?,
            userVerification: sel['userVerification'] as String?,
          );
        }

        final options = server.generateRegistrationOptions(
          userId: userId,
          username: username,
          userDisplayName: json['displayName'] as String?,
          authenticatorSelection: authenticatorSelection,
          attestation: json['attestation'] as String?,
        );

        await challengeStore.saveChallenge(sessionId, options.challenge);

        return _jsonResponse(options.toJson());
      } catch (e) {
        return _errorResponse(e);
      }
    });

    // 2. Verify Registration Response
    r.post('/register/verify', (Request request) async {
      try {
        final sessionId = getSessionId(request);
        final userId = getUserId(request);

        final expectedChallenge = await challengeStore.getAndConsumeChallenge(
          sessionId,
        );
        if (expectedChallenge == null) {
          return _errorJson('Challenge expired or missing', status: 403);
        }

        final json = await _readJson(request);

        final response = parseRegistrationResponseJson(json);

        final record = await server.verifyRegistrationResponse(
          response: response,
          expectedChallenge: expectedChallenge,
          userHandle: base64Url.decode(base64Url.normalize(userId)),
          existingCredentialCheck: (id) async {
            final idStr = base64Url.encode(id).replaceAll('=', '');
            return await credentialStore.isCredentialIdRegistered(idStr);
          },
        );

        await credentialStore.saveCredential(userId, record);

        return _jsonResponse({'status': 'success'});
      } catch (e) {
        return _errorResponse(e);
      }
    });

    // 3. Generate Authentication Options
    r.post('/authenticate/options', (Request request) async {
      try {
        final sessionId = getSessionId(request);

        final json = await _readJson(request);

        List<PublicKeyCredentialDescriptor>? allowCredentials;
        if (getAllowCredentials != null) {
          final list = await getAllowCredentials!(request, json);
          if (list.isNotEmpty) {
            allowCredentials = list;
          }
        }

        final options = server.generateAuthenticationOptions(
          allowCredentials: allowCredentials,
        );

        await challengeStore.saveChallenge(sessionId, options.challenge);

        return _jsonResponse(options.toJson());
      } catch (e) {
        return _errorResponse(e);
      }
    });

    // 4. Verify Authentication Response
    r.post('/authenticate/verify', (Request request) async {
      try {
        final sessionId = getSessionId(request);

        final expectedChallenge = await challengeStore.getAndConsumeChallenge(
          sessionId,
        );
        if (expectedChallenge == null) {
          return _errorJson('Challenge expired or missing', status: 403);
        }

        final json = await _readJson(request);

        final credentialId = json['id'] as String?;
        if (credentialId == null) {
          return _errorJson('Missing credential ID');
        }

        final storedCredential = await credentialStore.getCredential(
          credentialId,
        );
        if (storedCredential == null) {
          return _errorJson('Credential not found', status: 404);
        }

        final response = parseAuthenticationResponseJson(json);

        await server.verifyAuthenticationResponse(
          response: response,
          expectedChallenge: expectedChallenge,
          storedCredential: storedCredential,
        );

        return _jsonResponse({'status': 'success'});
      } catch (e) {
        return _errorResponse(e);
      }
    });

    return r;
  }
}
