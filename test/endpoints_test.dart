import 'dart:convert';
import 'package:test/test.dart';
import 'package:shelf/shelf.dart';
import 'package:shelf_webauthn/shelf_webauthn.dart';

class MockChallengeStore implements WebAuthnChallengeStore {
  final Map<String, String> _challenges = {};

  @override
  Future<void> saveChallenge(String sessionId, String challenge) async {
    _challenges[sessionId] = challenge;
  }

  @override
  Future<String?> getAndConsumeChallenge(String sessionId) async {
    return _challenges.remove(sessionId);
  }
}

class MockCredentialStore implements WebAuthnCredentialStore {
  final Map<String, CredentialRecord> _credentials = {};

  @override
  Future<void> saveCredential(
    String userId,
    CredentialRecord credential,
  ) async {
    _credentials[credential.credentialId] = credential;
  }

  @override
  Future<CredentialRecord?> getCredential(String credentialId) async {
    return _credentials[credentialId];
  }

  @override
  Future<bool> isCredentialIdRegistered(String credentialId) async {
    return _credentials.containsKey(credentialId);
  }
}

void main() {
  group('WebAuthnEndpoints', () {
    late WebAuthnServer server;
    late MockChallengeStore challengeStore;
    late MockCredentialStore credentialStore;
    late WebAuthnEndpoints endpoints;

    setUp(() {
      server = WebAuthnServer(
        rpId: 'localhost',
        expectedOrigin: 'http://localhost:8080',
      );
      challengeStore = MockChallengeStore();
      credentialStore = MockCredentialStore();
      endpoints = WebAuthnEndpoints(
        server: server,
        challengeStore: challengeStore,
        credentialStore: credentialStore,
        getSessionId: (req) => req.headers['x-session-id'] ?? 'session-123',
        getUserId: (req) => 'user-123',
      );
    });

    test('register/options returns JSON options and saves challenge', () async {
      final request = Request(
        'POST',
        Uri.parse('http://localhost:8080/register/options'),
        body: jsonEncode({'username': 'alice'}),
        headers: {
          'content-type': 'application/json',
          'x-session-id': 'session-123',
        },
      );

      final response = await endpoints.router(request);
      expect(response.statusCode, equals(200));
      expect(response.headers['content-type'], equals('application/json'));

      final body =
          jsonDecode(await response.readAsString()) as Map<String, dynamic>;
      expect(body, contains('challenge'));
      expect(body['user']['name'], equals('alice'));

      final saved = await challengeStore.getAndConsumeChallenge('session-123');
      expect(saved, equals(body['challenge']));
    });

    test('register/options returns JSON error on missing username', () async {
      final request = Request(
        'POST',
        Uri.parse('http://localhost:8080/register/options'),
        body: jsonEncode({}),
        headers: {'content-type': 'application/json'},
      );

      final response = await endpoints.router(request);
      expect(response.statusCode, equals(400));
      expect(response.headers['content-type'], equals('application/json'));

      final body =
          jsonDecode(await response.readAsString()) as Map<String, dynamic>;
      expect(body['error'], equals('Missing username'));
    });

    test(
      'register/options returns JSON error on malformed JSON request',
      () async {
        final request = Request(
          'POST',
          Uri.parse('http://localhost:8080/register/options'),
          body: '{bad-json',
          headers: {'content-type': 'application/json'},
        );

        final response = await endpoints.router(request);
        expect(response.statusCode, equals(400));
        expect(response.headers['content-type'], equals('application/json'));

        final body =
            jsonDecode(await response.readAsString()) as Map<String, dynamic>;
        expect(body['error'], contains('Malformed JSON body'));
      },
    );

    test('register/verify returns 403 when challenge is missing', () async {
      final request = Request(
        'POST',
        Uri.parse('http://localhost:8080/register/verify'),
        body: jsonEncode({}),
        headers: {
          'content-type': 'application/json',
          'x-session-id': 'session-empty',
        },
      );

      final response = await endpoints.router(request);
      expect(response.statusCode, equals(403));
      expect(response.headers['content-type'], equals('application/json'));

      final body =
          jsonDecode(await response.readAsString()) as Map<String, dynamic>;
      expect(body['error'], equals('Challenge expired or missing'));
    });
  });
}
