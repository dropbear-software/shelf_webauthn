# WebAuthn Registration Phase 2 Plan: Core Verification Algorithm

## Overview
This document outlines the second phase of implementing the WebAuthn "Registering a New Credential" ceremony (Section 7.1). This phase focuses on implementing the actual sequence of cryptographic and structural validation steps that the Relying Party (RP) must perform to securely register a new credential.

## Goals
1. Update the `CredentialRecord` model to hold all fields specified by Step 27 of the algorithm.
2. Implement the `verifyRegistrationResponse` method in `WebAuthnServer` to execute Steps 5-27 sequentially.
3. Integrate the existing parsing helpers (`CollectedClientData`, `AuthenticatorData`, `AttestationObject`).
4. Apply necessary cryptographic checks (SHA-256 hashing, CBOR validation).
5. Add unit tests for the complete registration verification flow using standard W3C vectors.

## Step-by-Step Implementation Plan

### Step 1: Update `CredentialRecord`
**File:** `lib/src/models/credential_record.dart`
- **Action:** Expand the model to include all fields required by Step 27 of Section 7.1.
- **New Properties:**
  - `credentialType` (String, default "public-key")
  - `uvInitialized` (bool)
  - `transports` (List<String>?)
  - `backupEligible` (bool)
  - `backupState` (bool)
  - `attestationObject` (Uint8List?) - optional
  - `attestationClientDataJSON` (Uint8List?) - optional
- Ensure value equality, `hashCode`, and `const` constructors are properly maintained.

### Step 2: Implement `verifyRegistrationResponse` Algorithm
**File:** `lib/src/shelf_webauthn_base.dart`
- **Action:** Replace the `UnimplementedError` with the 20+ steps defined in the W3C spec.
- **Required Additional Parameters:**
  - `requireUserVerification` (bool, default `false`)
  - `allowedAlgs` (List<int>?, optional, to check against `pubKeyCredParams`)
  - `existingCredentialCheck` (Future<bool> Function(Uint8List credentialId)?, optional callback for Step 26)
- **Algorithm Flow (Referencing Spec Steps):**
  - **Steps 5-6:** Parse `clientDataJSON` using `CollectedClientData.parse()`.
  - **Steps 7-11:** Call `clientData.verify()` checking `expectedType: ClientDataType.create`, `expectedChallenge`, `expectedOrigin`.
  - **Step 12:** Compute SHA-256 hash of `response.clientDataJSON`.
  - **Step 13:** Parse `attestationObject` using `AttestationObject.parse()`.
  - **Step 14:** Compute SHA-256 of `rpId` and verify it matches `authData.rpIdHash`.
  - **Step 15:** Verify User Present (`UP`) bit is set in `authData.flags`.
  - **Step 16:** If `requireUserVerification` is true, verify User Verified (`UV`) bit is set.
  - **Step 17:** If `BE` is not set, verify `BS` is not set.
  - **Steps 18-19:** Backup eligibility/state flow (informational, store in record).
  - **Step 20:** Verify the `alg` of the credential public key is acceptable (supported or in `allowedAlgs`).
  - **Steps 21-24:** Attestation validation. For now, if `fmt` == `"none"`, instantiate `NoneAttestationVerifier` and call `verify()`. If any other format, throw `UnsupportedAttestationFormatException` (or similar).
  - **Step 25:** Verify `credentialId` length <= 1023 bytes.
  - **Step 26:** Check if `credentialId` is already registered (using the optional callback).
  - **Step 27:** Construct and return the comprehensive `CredentialRecord`.

### Step 3: Implement Unit Tests
**File:** `test/shelf_webauthn_test.dart` (or `registration_test.dart`)
- **Action:** Test the full `verifyRegistrationResponse` flow.
- **Implementation:**
  - Setup a `WebAuthnServer` instance with `rpId` = "example.org", `expectedOrigin` = "https://example.org".
  - Feed it the "sctn-test-vectors-none-es256" registration vector.
  - Mock the base64url decoded challenge expected.
  - Assert that the returned `CredentialRecord` is correctly populated with the expected `credentialId`, `publicKey`, `signCount`, and flags.
  - Add failure tests: invalid challenge, origin mismatch, missing UP flag.

## Success Criteria
Phase 2 will be considered complete when the `verifyRegistrationResponse` method successfully orchestrates all spec requirements, seamlessly chaining the Phase 1 parsers together, and the entire flow passes against the W3C test vectors.
