# Authenticator Data Parsing Plan

**Status: COMPLETED**

## 1. Objective
Our immediate goal is to implement the parser for the `authenticatorData` (authData) binary structure. This is a critical component of the WebAuthn standard as it contains the core cryptographic state from the authenticator, including the Replay Protection signature count, boolean flags (like User Present), and the newly generated Public Key during registration.

## 2. Background: What is `authenticatorData`?
According to Section 6.1 of the WebAuthn specification, `authenticatorData` is a compact binary byte array. It does not use JSON or CBOR for its outer structure; instead, it relies on fixed-length and variable-length byte offsets.

The structure is laid out exactly as follows:

| Field | Length | Description |
| :--- | :--- | :--- |
| `rpIdHash` | 32 bytes | SHA-256 hash of the Relying Party ID. |
| `flags` | 1 byte | Bitfield indicating User Present (UP), User Verified (UV), Attested Credential Data included (AT), and Extension Data included (ED). |
| `signCount` | 4 bytes | 32-bit unsigned big-endian integer for replay protection. |
| `attestedCredentialData` | Variable | **(Only present if the AT flag is set)** Contains the AAGUID, Credential ID, and the COSE Public Key. |
| `extensions` | Variable | **(Only present if the ED flag is set)** CBOR map of extension data. |

### 2.1 The `attestedCredentialData` Structure
If the AT flag (bit 6) is set (which is true during a Registration ceremony), the bytes immediately following `signCount` contain the `attestedCredentialData`:

| Field | Length | Description |
| :--- | :--- | :--- |
| `aaguid` | 16 bytes | Authenticator Attestation GUID. |
| `credentialIdLength` | 2 bytes | 16-bit unsigned big-endian integer (let's call it `L`). |
| `credentialId` | `L` bytes | The credential ID. |
| `credentialPublicKey`| Variable | A CBOR-encoded map representing a `COSE_Key`. |

## 3. Implementation Plan

To correctly parse this in Dart, we will follow a systematic approach:

### Step 1: Create the Data Models
We need to define a Dart class to represent the parsed data.
```dart
class AuthenticatorData {
  final List<int> rpIdHash;
  final int flags;
  final int signCount;
  
  // Optional fields from attestedCredentialData
  final List<int>? aaguid;
  final List<int>? credentialId;
  final Map<dynamic, dynamic>? credentialPublicKey; // The decoded COSE Key
  
  // ... getters for specific flags like `isUserPresent`, `hasAttestedCredentialData`
}
```

### Step 2: Build the Byte Reader Utility
Because `authenticatorData` mixes fixed offsets with variable-length CBOR maps, we cannot use a simple `ByteData` view for the whole thing. We will build a small parsing function that iterates through the byte array:
1. Slice the first 32 bytes for `rpIdHash`.
2. Read the 33rd byte for `flags`.
3. Read bytes 34-37 as a big-endian uint32 for `signCount`.
4. If the AT flag is set, continue slicing:
   - Next 16 bytes for `aaguid`.
   - Next 2 bytes for `credentialIdLength`.
   - Next `credentialIdLength` bytes for `credentialId`.
   - Take the *remaining* bytes and feed them into the `cbor` package.
5. Extract the parsed CBOR map as the `credentialPublicKey`.

### Step 3: Implement COSE to WebCrypto Mapping
Once we have the CBOR map for the `credentialPublicKey`, we will look at the `alg` (algorithm) parameter (key `3` in the map). 
- If `alg == -7` (ES256), we extract the X (`-2`) and Y (`-3`) coordinates and format them for `webcrypto`'s ECDSA instantiation.
- If `alg == -257` (RS256), we extract the modulus (`-1`) and exponent (`-2`) for `webcrypto`'s RSA instantiation.

### Step 4: Test against W3C Vectors
We will write tests in `test/auth_data_test.dart`. Using the `testVectors` we extracted earlier, we will take the raw `authenticatorData` hex strings, run them through our parser, and assert that the extracted `credentialId`, `signCount`, and flags match the expected output.

## 4. Next Steps
If this plan looks acceptable, we will proceed to create `lib/src/helpers/auth_data.dart` and implement the parsing logic outlined in Step 1 and Step 2.

To resume this session: gemini --resume a8138a5c-13ed-4f61-add3-c2a32a5d329f 