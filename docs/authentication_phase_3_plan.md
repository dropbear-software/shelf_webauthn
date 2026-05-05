# WebAuthn Authentication Phase 3 Plan: Core Verification Algorithm

## Overview
This document outlines the third phase of implementing the WebAuthn Server: the "Verifying an Authentication Assertion" ceremony (Section 7.2). This phase focuses on parsing the `AuthenticatorAssertionResponse` and verifying the cryptographic signature over the authentication data to prove the user possesses the credential.

## Goals
1. Update `AuthenticatorAssertionResponse` model to hold all required fields (`clientDataJSON`, `authenticatorData`, `signature`, `userHandle`).
2. Implement the `verifyAuthenticationResponse` method in `WebAuthnServer` to execute the sequence of steps defined in Section 7.2.
3. Validate `clientDataJSON` and `authenticatorData` similar to the registration phase.
4. Cryptographically verify the ECDSA/RSA `signature` against the previously stored `credentialPublicKey`.
5. Update the `signCount` and `backupState` in the `CredentialRecord`.
6. Add unit tests for the complete authentication verification flow using standard W3C vectors.

## Step-by-Step Implementation Plan

### Step 1: Update `AuthenticatorAssertionResponse`
**File:** `lib/src/models/responses.dart`
- **Action:** Expand the model to include all fields.
- **Properties:**
  - `clientDataJSON` (Uint8List)
  - `authenticatorData` (Uint8List)
  - `signature` (Uint8List)
  - `userHandle` (Uint8List?) - optional
- Ensure value equality, `hashCode`, and `const` constructors are properly maintained.

### Step 2: Implement `verifyAuthenticationResponse` Algorithm
**File:** `lib/src/shelf_webauthn_base.dart`
- **Action:** Replace the `UnimplementedError` with the steps defined in the W3C spec (Section 7.2).
- **Algorithm Flow (Referencing Spec Steps):**
  - **Steps 7-10:** Parse and verify `clientDataJSON` using `CollectedClientData.parse()` and `.verify()`. Expected type is `"webauthn.get"`.
  - **Step 11:** Verify `clientData.origin` against `expectedOrigin`.
  - **Step 12-13:** (crossOrigin/topOrigin verification - typically pass-through unless specific RP policy).
  - **Step 14:** Verify `rpIdHash` in `authData` matches the SHA-256 hash of `rpId`.
  - **Step 15:** Verify User Present (`UP`) bit is set in `authData.flags`.
  - **Step 16:** If `requireUserVerification` is true, verify User Verified (`UV`) bit is set.
  - **Step 17:** If `BE` is not set, verify `BS` is not set.
  - **Step 18:** Verify backup state changes against the `storedCredential`.
  - **Step 19:** Compute the SHA-256 hash of `clientDataJSON` (`clientDataHash`).
  - **Step 20:** **Signature Verification**
    - Concatenate `authenticatorData` and `clientDataHash`.
    - Decode the `storedCredential.publicKey` (which is CBOR) and convert to a `webcrypto` PublicKey (using the logic in `cose.dart`).
    - Use the `webcrypto` key to verify the `signature` over the concatenated data.
  - **Step 21:** Verify and update `signCount` to detect cloning.
  - **Step 23:** Update `CredentialRecord` state (`signCount`, `backupState`, `uvInitialized`).
  - **Step 24:** Return a successful `VerificationResult`.

### Step 3: Implement Unit Tests
**File:** `test/shelf_webauthn_test.dart`
- **Action:** Test the full `verifyAuthenticationResponse` flow.
- **Implementation:**
  - Create a new `group('WebAuthnServer.verifyAuthenticationResponse')`.
  - Setup a `WebAuthnServer` instance.
  - Use the "authentication" part of the `sctn-test-vectors-none-es256` test vector.
  - Mock a `CredentialRecord` matching the public key from the registration vector.
  - Assert that the returned `VerificationResult` is `success: true` and the `updatedSignCount` matches.
  - Add failure tests: invalid challenge, invalid signature, origin mismatch.

## Success Criteria
Phase 3 will be considered complete when the `verifyAuthenticationResponse` method successfully orchestrates all spec requirements, the cryptographic signature is verified using `webcrypto`, and the entire flow passes against the W3C test vectors.