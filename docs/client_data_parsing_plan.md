# Client Data JSON Parsing Plan

**Status: COMPLETED**

## 1. Objective
Our goal is to implement the parser and validator for `clientDataJSON`. This structure is created by the browser and contains critical contextual information about the WebAuthn ceremony, such as the Relying Party origin and the challenge.

## 2. Background: What is `clientDataJSON`?
According to Section 5.8.1 of the WebAuthn specification, `clientDataJSON` is a UTF-8 encoded JSON string. While the spec provides a "Limited Verification Algorithm" for constrained environments, we will implement a full JSON parser to ensure maximum compatibility with future extensions.

The `CollectedClientData` dictionary contains the following fields:

| Field | Type | Description |
| :--- | :--- | :--- |
| `type` | String | Either `"webauthn.create"` (registration) or `"webauthn.get"` (authentication). |
| `challenge` | String | The base64url-encoded challenge from the server. |
| `origin` | String | The fully qualified origin of the requester (e.g., `https://example.com`). |
| `crossOrigin` | Boolean | (Optional) Indicates if the request was made from a cross-origin context. |
| `topOrigin` | String | (Optional) The origin of the top-level browsing context. |

## 3. Implementation Plan

### Step 1: Create the Data Model
We will define a `CollectedClientData` class in `lib/src/helpers/client_data.dart`.
```dart
class CollectedClientData {
  final String type;
  final String challenge;
  final String origin;
  final bool? crossOrigin;
  final String? topOrigin;
  // ... extra fields for future-proofing
  final Map<String, dynamic> rawData;
}
```

### Step 2: Implement the Parser
The parser will:
1. Decode the raw bytes using `utf8.decode()`.
2. Parse the resulting string using `json.decode()`.
3. Map the JSON fields to the `CollectedClientData` model.
4. Store any unknown fields in a `rawData` map to satisfy the spec's requirement for extensibility.

### Step 3: Implement Validation Logic
We will add a `verify()` method (or a set of validator functions) to check:
1. **Type**: Does it match the expected ceremony (`webauthn.create` or `webauthn.get`)?
2. **Challenge**: Does the decoded challenge bytes match the original challenge issued by the server?
3. **Origin**: Does the origin match the expected Relying Party origin?
4. **CrossOrigin**: If the server does not allow cross-origin requests, verify this is false or absent.

### Step 4: Test against W3C Vectors
We will create `test/client_data_test.dart` and use the `clientDataJSON` hex strings from `test/vectors.dart`. We will verify:
- Successful parsing of valid JSON.
- Rejection of mismatched challenges or origins.
- Correct handling of base64url padding (WebAuthn challenges are often unpadded).

## 4. Next Steps
1. Create `lib/src/helpers/client_data.dart` with the model and parser.
2. Implement validation logic.
3. Add unit tests.
