# WebAuthn Client .NET
FIDO2 WebAuthn client (ie. password manager) implementation in .NET

Simulates response to WebAuthn registration and authentication requests from server. Primarily aimed for use in automating authentication to FIDO2-enabled authentication scheme, hence security management is not of main objective and therefore should only be used when no other secure method exists.

## Note

Initialize `FIDOWebAuthn` and call `.Create()` and `.Get()` for main functionality. Accepts and returns an object that could be `JsonSerializer.Serialize`d into string mostly compatible with `navigator.credentials.create()` and `navigator.credentials.get()` in `PublicKeyCredential` mode. Some properties where an actual browser would expect an `ArrayBuffer` are processed as Base64URL encoded string instead. 

More info: https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API

## Private Key Storage

Default implementation stores all keys as plain text into a CSV file. An optional `Encryptor` and `Decryptor` delegate can be provided for more secure private key handling. Extension to other storage options can be done by implementing `ICredentialStorage`.

## Cryptographic provider

Support for limited cryptographic schemes are available: ES256(-7), RS256(-257). More scheme support can be added by implementing additional `ICryptographicProvider` and `CborHelper.EncodeCoseKey` for the scheme.
