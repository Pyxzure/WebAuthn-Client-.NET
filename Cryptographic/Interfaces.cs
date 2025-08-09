namespace WebAuthn_Client_.NET.Cryptographic
{

    // Cryptographic algorithm support
    public enum CoseAlgorithm
    {
        ES256 = -7,     // ECDSA w/ SHA-256
        RS256 = -257,   // RSASSA-PKCS1-v1_5 w/ SHA-256
        PS256 = -37,    // RSASSA-PSS w/ SHA-256
        EdDSA = -8      // EdDSA signature algorithms
    }

    public interface ICryptographicProvider
    {
        // privateKey, publicKey: Base64 encoded string
        (string publicKey, string privateKey) GenerateKeyPair();
        byte[] Sign(byte[] data, string privateKey);
        bool Verify(byte[] data, byte[] signature, string publicKey);
        CoseAlgorithm Algorithm { get; }

        // Throws if the public key is invalid or cannot be parsed
        byte[] GetPublicKeyBytes(string publicKey);
    }
}
