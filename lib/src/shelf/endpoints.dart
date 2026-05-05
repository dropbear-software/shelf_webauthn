import 'dart:convert';
import 'package:shelf/shelf.dart';
import 'package:shelf_router/shelf_router.dart';
import '../shelf_webauthn_base.dart';
import '../models/models.dart';
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

        final body = await request.readAsString();
        final json = jsonDecode(body) as Map<String, dynamic>;

        final username = json['username'] as String?;
        if (username == null) {
          return Response.badRequest(body: 'Missing username');
        }

        final options = server.generateRegistrationOptions(
          userId: userId,
          username: username,
          userDisplayName: json['displayName'] as String?,
        );

        await challengeStore.saveChallenge(sessionId, options.challenge);

        return Response.ok(
          jsonEncode(options.toJson()),
          headers: {'content-type': 'application/json'},
        );
      } catch (e) {
        return Response.internalServerError(body: e.toString());
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
          return Response.forbidden('Challenge expired or missing');
        }

        final body = await request.readAsString();
        final json = jsonDecode(body) as Map<String, dynamic>;

        final response = parseRegistrationResponseJson(json);

        final record = await server.verifyRegistrationResponse(
          response: response,
          expectedChallenge: expectedChallenge,
          existingCredentialCheck: (id) async {
            final idStr = base64Url.encode(id).replaceAll('=', '');
            return await credentialStore.isCredentialIdRegistered(idStr);
          },
        );

        await credentialStore.saveCredential(userId, record);

        return Response.ok(
          '{"status":"success"}',
          headers: {'content-type': 'application/json'},
        );
      } catch (e) {
        return Response.badRequest(body: e.toString());
      }
    });

    // 3. Generate Authentication Options
    r.post('/authenticate/options', (Request request) async {
      try {
        final sessionId = getSessionId(request);

        final body = await request.readAsString();
        final json = body.isNotEmpty
            ? jsonDecode(body) as Map<String, dynamic>
            : <String, dynamic>{};

        List<PublicKeyCredentialDescriptor>? allowCredentials;
        if (getAllowCredentials != null) {
          allowCredentials = await getAllowCredentials!(request, json);
        }

        final options = server.generateAuthenticationOptions(
          allowCredentials: allowCredentials,
        );

        await challengeStore.saveChallenge(sessionId, options.challenge);

        return Response.ok(
          jsonEncode(options.toJson()),
          headers: {'content-type': 'application/json'},
        );
      } catch (e) {
        return Response.internalServerError(body: e.toString());
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
          return Response.forbidden('Challenge expired or missing');
        }

        final body = await request.readAsString();
        final json = jsonDecode(body) as Map<String, dynamic>;

        final credentialId = json['id'] as String?;
        if (credentialId == null) {
          return Response.badRequest(body: 'Missing credential ID');
        }

        final storedCredential = await credentialStore.getCredential(
          credentialId,
        );
        if (storedCredential == null) {
          return Response.notFound('Credential not found');
        }

        final response = parseAuthenticationResponseJson(json);

        await server.verifyAuthenticationResponse(
          response: response,
          expectedChallenge: expectedChallenge,
          storedCredential: storedCredential,
        );

        return Response.ok(
          '{"status":"success"}',
          headers: {'content-type': 'application/json'},
        );
      } catch (e) {
        return Response.badRequest(body: e.toString());
      }
    });

    return r;
  }
}
