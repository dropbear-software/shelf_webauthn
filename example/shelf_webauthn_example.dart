import 'dart:convert';
import 'dart:io';
import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart' as shelf_io;
import 'package:shelf_webauthn/shelf_webauthn.dart';
import 'package:shelf_router/shelf_router.dart';

// 1. Implement the Challenge Store (In-Memory for example purposes)
class InMemoryChallengeStore implements WebAuthnChallengeStore {
  final _challenges = <String, String>{};

  @override
  Future<void> saveChallenge(String sessionId, String challenge) async {
    _challenges[sessionId] = challenge;
  }

  @override
  Future<String?> getAndConsumeChallenge(String sessionId) async {
    return _challenges.remove(sessionId);
  }
}

// 2. Implement the Credential Store (In-Memory for example purposes)
class InMemoryCredentialStore implements WebAuthnCredentialStore {
  final _credentials = <String, CredentialRecord>{};
  final _userCredentials = <String, List<String>>{};

  @override
  Future<void> saveCredential(
    String userId,
    CredentialRecord credential,
  ) async {
    _credentials[credential.credentialId] = credential;
    _userCredentials.putIfAbsent(userId, () => []).add(credential.credentialId);
  }

  @override
  Future<CredentialRecord?> getCredential(String credentialId) async {
    return _credentials[credentialId];
  }

  @override
  Future<bool> isCredentialIdRegistered(String credentialId) async {
    return _credentials.containsKey(credentialId);
  }

  List<String> getUserCredentialIds(String userId) {
    return _userCredentials[userId] ?? [];
  }
}

void main() async {
  // 3. Initialize the core WebAuthn Server logic
  final webAuthn = WebAuthnServer(
    rpId: 'localhost',
    expectedOrigin: 'http://localhost:8080',
  );

  // 4. Initialize the stores
  final challengeStore = InMemoryChallengeStore();
  final credentialStore = InMemoryCredentialStore();

  // 5. Wire up the Endpoints Router
  final endpoints = WebAuthnEndpoints(
    server: webAuthn,
    challengeStore: challengeStore,
    credentialStore: credentialStore,
    // In a real app, you would extract this from a session cookie
    getSessionId: (Request request) =>
        request.headers['x-session-id'] ?? 'dummy-session',
    // In a real app, you would extract this from an authenticated user's session
    // WebAuthn requires the User ID to be a byte array, so we pass it as a base64url string in JSON.
    getUserId: (Request request) =>
        base64Url.encode(utf8.encode('dummy-user-id')).replaceAll('=', ''),
    // Provide allowed credentials so authenticators know which keys to check for
    getAllowCredentials: (Request request, Map<String, dynamic> body) async {
      // If username-less passkey login, keep allowCredentials empty so browser searches resident keys
      if (body['username-less'] == true) {
        return [];
      }

      // In this simple demo, we fetch all credentials registered for our dummy user
      final dummyUserId = base64Url
          .encode(utf8.encode('dummy-user-id'))
          .replaceAll('=', '');
      final credIds = credentialStore.getUserCredentialIds(dummyUserId);

      if (credIds.isEmpty) return [];

      return credIds
          .map((id) => PublicKeyCredentialDescriptor(id: id))
          .toList();
    },
  );

  final appRouter = Router();
  appRouter.mount('/', endpoints.router.call);

  appRouter.get('/', (Request request) async {
    final file = File('example/index.html');
    if (await file.exists()) {
      return Response.ok(
        file.openRead(),
        headers: {'content-type': 'text/html'},
      );
    }
    return Response.notFound('index.html not found');
  });

  appRouter.get('/passkey/', (Request request) async {
    final file = File('example/passkey.html');
    if (await file.exists()) {
      return Response.ok(
        file.openRead(),
        headers: {'content-type': 'text/html'},
      );
    }
    return Response.notFound('passkey.html not found');
  });

  appRouter.get('/passkey', (Request request) async {
    return Response.movedPermanently('/passkey/');
  });

  // 6. Build the pipeline
  final handler = const Pipeline()
      .addMiddleware(logRequests())
      .addHandler(appRouter.call);

  // 7. Serve the API
  final server = await shelf_io.serve(handler, 'localhost', 8080);
  print('WebAuthn API serving at http://${server.address.host}:${server.port}');
  print('Open your browser and navigate to http://localhost:8080');
}
