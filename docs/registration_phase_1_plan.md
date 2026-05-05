# WebAuthn Registration Phase 1 Plan: Attestation Parsing & Models

## Overview
This document outlines the first phase of implementing the WebAuthn "Registering a New Credential" ceremony (Section 7.1). The focus of this phase is on data structures, CBOR decoding, and the "none" attestation format, stopping short of the complete verification pipeline. This scopes the work to taking raw bytes from the client and reliably turning them into strongly-typed Dart objects.

## Goals
1. Flesh out the `AuthenticatorAttestationResponse` model to accurately hold raw payload data.
2. Build an `AttestationObject` model and parser using `cbor`.
3. Implement a base structure for Attestation Statement verification, along with the concrete `"none"` format.
4. Add comprehensive tests using W3C test vectors (`test/vectors.dart`).

## Step-by-Step Implementation Plan

### Step 1: Update `AuthenticatorAttestationResponse`
**File:** `lib/src/shelf_webauthn_base.dart` (or potentially extract to `lib/src/helpers/attestation_response.dart`)
- **Action:** Update the current stub.
- **Properties:**
  - `clientDataJSON`: `Uint8List`
  - `attestationObject`: `Uint8List`
  - `transports`: `List<String>?` (Optional)
- **Validation:** Add basic length/null checks if necessary, though most parsing will happen downstream.

### Step 2: Create `AttestationObject` Model and Parser
**File:** `lib/src/helpers/attestation_object.dart`
- **Action:** Create a new class to represent the decoded `attestationObject`.
- **Properties:**
  - `fmt`: `String` (e.g., "none", "packed", "fido-u2f")
  - `authData`: `AuthenticatorData` (reusing the existing `AuthenticatorData.parse`)
  - `attStmt`: `Map<String, dynamic>` (raw decoded CBOR map for the statement)
- **Parser (`AttestationObject.parse(Uint8List data)`):**
  1. Decode the top-level `Uint8List` using `cbor` (or the existing `decodeOne` in `cbor_utils.dart`).
  2. Assert the result is a CBOR Map.
  3. Extract `fmt` (string), `authData` (byte string), and `attStmt` (map).
  4. Pass the `authData` byte string to `AuthenticatorData.parse(authDataBytes)`.
  5. Return the strongly-typed `AttestationObject`.

### Step 3: Implement Attestation Statement Verification Base & "none" Format
**File:** `lib/src/helpers/attestation_statement.dart`
- **Action:** Define the verification interface and implement the "none" format.
- **Structure:**
  - `abstract class AttestationStatementVerifier`
    - `Future<void> verify(Map<String, dynamic> attStmt, AuthenticatorData authData, Uint8List clientDataHash)`
  - `class NoneAttestationVerifier extends AttestationStatementVerifier`
    - **Implementation:** For the `"none"` format, `attStmt` MUST be empty. If it's not empty, throw an exception. Otherwise, return success.

### Step 4: Unit Testing with W3C Test Vectors
**File:** `test/attestation_object_test.dart` (New file)
- **Action:** Write tests to ensure our parsing logic works against the spec's official test vectors.
- **Implementation:**
  - Import `test/vectors.dart`.
  - Iterate through `testVectors`.
  - For vectors where the registration payload includes `attestationObject` (e.g., `sctn-test-vectors-none-es256`):
    - Base16/Hex decode the `attestationObject` from the test vector.
    - Call `AttestationObject.parse()`.
    - Assert that `fmt` matches expectations (e.g., "none").
    - Assert that `authData.credentialId` and `authData.aaguid` map correctly to the test vector's expected values.
  - Implement a specific test to assert that `NoneAttestationVerifier` succeeds on an empty `attStmt` and fails on a populated one.

## Success Criteria
Phase 1 will be considered complete when:
- We can successfully decode an `attestationObject` from a raw byte array.
- The W3C test vectors for registration (specifically parsing the `attestationObject` and its nested `authData`) pass.
- We have the foundational types necessary to implement the full Phase 2 (orchestrating the 21 steps of Section 7.1 validation).
