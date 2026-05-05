## 0.1.0
- Initial version.
- **Feature**: Implemented core registration (`verifyRegistrationResponse`) and authentication (`verifyAuthenticationResponse`) verification algorithms (W3C Spec Sections 7.1 & 7.2).
- **Feature**: Implemented options generation methods (`generateRegistrationOptions`, `generateAuthenticationOptions`).
- **Feature**: Added high-level `shelf` integration via the new `WebAuthnEndpoints` router builder.
- **Feature**: Added JSON parsers for client data payloads.
- **Enhancement**: Extracted strongly-typed WebAuthn data models into `lib/src/models/`.
- **Enhancement**: Implemented `convertDerToRawEcdsaSignature` to handle ASN.1 DER to raw signature conversion for webcrypto.
- **Documentation**: Updated example app to serve a functional, end-to-end HTML/JS demo.
- **Testing**: Added comprehensive unit test coverage using official W3C test vectors.
