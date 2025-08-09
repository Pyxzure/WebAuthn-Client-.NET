using System.Security.Cryptography;

namespace WebAuthn_Client_.NET.Cryptographic
{
    public class RS256Provider : ICryptographicProvider
    {
        public CoseAlgorithm Algorithm => CoseAlgorithm.RS256;

        public (string publicKey, string privateKey) GenerateKeyPair()
        {
            using (var rsa = RSA.Create(2048))
            {
                var privateKey = Convert.ToBase64String(rsa.ExportRSAPrivateKey());
                var publicKey = Convert.ToBase64String(rsa.ExportRSAPublicKey());
                return (publicKey, privateKey);
            }
        }

        public byte[] Sign(byte[] data, string privateKey)
        {
            using (var rsa = RSA.Create())
            {
                rsa.ImportRSAPrivateKey(Convert.FromBase64String(privateKey), out _);
                return rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
        }

        public bool Verify(byte[] data, byte[] signature, string publicKey)
        {
            using (var rsa = RSA.Create())
            {
                rsa.ImportRSAPublicKey(Convert.FromBase64String(publicKey), out _);
                return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
        }

        public byte[] GetPublicKeyBytes(string publicKey)
        {
            using (var rsa = RSA.Create())
            {
                rsa.ImportRSAPublicKey(Convert.FromBase64String(publicKey), out _);
                var parameters = rsa.ExportParameters(false);

                // Return the modulus for RSA public key
                return parameters.Modulus!;
            }
        }
    }
}
