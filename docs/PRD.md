# Product Requirements Document: Shelf WebAuthn

## 1. Objective
Develop a robust, server-side WebAuthentication (WebAuthn) Relying Party (RP) implementation for the Dart ecosystem, specifically tailored for integration with the `shelf` HTTP server framework. This package will allow Dart backend developers to easily add passkey, biometrics, and security key authentication to their web applications.

## 2. Scope
*   **In Scope:** 
    *   Implementing Relying Party (RP) operations as defined in Section 7 of the W3C Web Authentication specification.
    *   Parsing and validating `AuthenticatorAttestationResponse` (Registration).
    *   Parsing and validating `AuthenticatorAssertionResponse` (Authentication).
    *   CBOR decoding for `authData` and `attestationObject`.
    *   COSE key parsing (specifically ES256 and RS256 algorithms) and mapping to Dart `webcrypto` objects.
    *   Cryptographic signature verification.
    *   "None" and "Self" attestation validation.
    *   Helper classes/functions for generating valid challenge payloads (Creation and Request options).
*   **Out of Scope (Initially):**
    *   Full FIDO Metadata Service (MDS) integration for strict hardware attestation (can be added later as an extension).
    *   Parsing X.509 certificate chains for complex attestation formats (`packed`, `android-key`, `tpm`) beyond basic signature verification.
    *   Database implementation (the package will define the `CredentialRecord` interface, but the developer must implement the actual database storage).

## 3. Core Dependencies
*   **`cbor`:** For decoding binary map structures (`attestationObject`, `authData`).
*   **`webcrypto`:** For instantiation of asymmetric public keys and signature verification (ECDSA, RSA).
*   **`crypto`:** For SHA-256 hashing (e.g., `clientDataHash`, `rpIdHash`).
*   **`shelf`:** The target framework, potentially providing abstract Request/Response helpers or middleware.

## 4. Functional Requirements

### 4.1 Registration (MakeCredential)
The package must provide functions to handle the two phases of registration:
1.  **Generate Creation Options:** Create cryptographically secure random challenges and format the `PublicKeyCredentialCreationOptions` JSON for the client.
2.  **Verify Attestation:** Execute the ~20 step verification process from Spec Section 7.1:
    *   Verify `clientDataJSON` (`type`, `challenge`, `origin`).
    *   Verify `rpIdHash` against the server's expected Relying Party ID.
    *   Verify User Present (UP) and User Verified (UV) flags in `authData`.
    *   Extract and decode the COSE Public Key into a usable `webcrypto` object.
    *   Validate the `attStmt` (Attestation Statement).
    *   Output a `CredentialRecord` object containing the `credentialId`, `publicKey`, and initial `signCount` to be stored by the developer.

### 4.2 Authentication (GetAssertion)
The package must provide functions to handle the two phases of authentication:
1.  **Generate Request Options:** Create secure random challenges and format the `PublicKeyCredentialRequestOptions` JSON for the client.
2.  **Verify Assertion:** Execute the verification process from Spec Section 7.2:
    *   Verify `clientDataJSON` (`type`, `challenge`, `origin`).
    *   Look up the stored `CredentialRecord` via the provided `credentialId`.
    *   Verify `rpIdHash` and flags.
    *   Compute the `clientDataHash` and verify the cryptographic signature over `(authData + clientDataHash)` using the stored public key.
    *   Perform replay protection by validating that the incoming `signCount` is greater than the stored `signCount`.
    *   Return success and the updated `signCount` to be persisted.

## 5. Data Models
The package will expose strongly-typed Dart classes for all WebAuthn data structures, including:
*   `PublicKeyCredentialCreationOptions`
*   `PublicKeyCredentialRequestOptions`
*   `AuthenticatorAttestationResponse`
*   `AuthenticatorAssertionResponse`
*   `CollectedClientData`
*   `AuthenticatorData` (Parsed CBOR flags and COSE key)
*   `CredentialRecord` (The entity to be stored in the RP database)

## 6. API Design (Draft)
The package should strive for a functional, stateless core that is easy to test, wrapped in optional `shelf` helpers.

```dart
// Example Conceptual API
class WebAuthnServer {
  final String rpId;
  final String expectedOrigin;

  WebAuthnServer({required this.rpId, required this.expectedOrigin});

  // Phase 1: Registration
  PublicKeyCredentialCreationOptions generateRegistrationOptions(User user);
  Future<CredentialRecord> verifyRegistrationResponse(
      AuthenticatorAttestationResponse response, 
      String expectedChallenge);

  // Phase 2: Authentication
  PublicKeyCredentialRequestOptions generateAuthenticationOptions(String? username);
  Future<VerificationResult> verifyAuthenticationResponse(
      AuthenticatorAssertionResponse response,
      String expectedChallenge,
      CredentialRecord storedCredential);
}
```

## 7. Testing & Validation
The package will be rigorously tested against the official W3C WebAuthn Specification Test Vectors (Section 16).

*   **Official W3C Test Vectors:** Implement test suites using the CDDL-notated byte strings from the spec for both Registration and Authentication ceremonies. This includes verifying:
    *   **Algorithms:** ES256, ES384, ES512, RS256, and EdDSA (Ed25519/Ed448) credentials.
    *   **Attestation Types:** No Attestation ("none"), Self Attestation, and "packed" attestation.
    *   **Edge Cases:** Payloads with `"crossOrigin": true`, `"topOrigin"` included, and very long credential IDs.
*   **Component-Level Unit Tests:** 
    *   Unit tests for CBOR parsing and COSE key extraction to ensure reliable conversion to Dart `webcrypto` objects.
    *   Unit tests for correct SHA-256 hashing (`clientDataHash`, `rpIdHash`).
    *   Unit tests for cryptographic signature verification (ECDSA/RSA).
*   **Negative Testing & Validation:** 
    *   Validation against incorrect origins, mismatched challenge payloads, and wrong RP IDs.
    *   Rejection of bad cryptographic signatures.
    *   Replay protection verification (ensuring authentication fails if `signCount` is not strictly greater than the stored value).
