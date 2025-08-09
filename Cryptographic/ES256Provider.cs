using System.Formats.Asn1;
using System.Security.Cryptography;

namespace WebAuthn_Client_.NET.Cryptographic
{
    public class ES256Provider : ICryptographicProvider
    {
        public CoseAlgorithm Algorithm => CoseAlgorithm.ES256;

        public (string publicKey, string privateKey) GenerateKeyPair()
        {
            using (var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            {
                var privateKey = Convert.ToBase64String(ecdsa.ExportECPrivateKey());
                var publicKey = Convert.ToBase64String(ecdsa.ExportSubjectPublicKeyInfo());
                return (publicKey, privateKey);
            }
        }

        public byte[] Sign(byte[] data, string privateKey)
        {
            using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            ecdsa.ImportECPrivateKey(Convert.FromBase64String(privateKey), out _);
            //ecdsa.ImportPkcs8PrivateKey(Convert.FromBase64String(privateKey), out _);
            var rawSignature = ecdsa.SignData(data, HashAlgorithmName.SHA256);
            return RawToDer(rawSignature, 32);
        }

        public bool Verify(byte[] data, byte[] signature, string publicKey)
        {
            using (var ecdsa = ECDsa.Create())
            {
                ecdsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKey), out _);
                return ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256);
            }
        }

        public byte[] GetPublicKeyBytes(string publicKey)
        {
            using (var ecdsa = ECDsa.Create())
            {
                ecdsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKey), out _);
                var parameters = ecdsa.ExportParameters(false);

                // Return uncompressed point format: 0x04 || x || y
                var result = new byte[1 + parameters.Q.X!.Length + parameters.Q.Y!.Length];
                result[0] = 0x04; // Uncompressed point indicator
                Array.Copy(parameters.Q.X, 0, result, 1, parameters.Q.X.Length);
                Array.Copy(parameters.Q.Y, 0, result, 1 + parameters.Q.X.Length, parameters.Q.Y.Length);
                return result;
            }
        }

        // Convert DER (ASN.1 SEQUENCE of two INTEGERs) -> raw r||s (padded to size each)
        private static byte[] DerToRaw(byte[] derSig, int coordSize)
        {
            var reader = new AsnReader(derSig, AsnEncodingRules.DER);
            var seq = reader.ReadSequence();
            var r = seq.ReadIntegerBytes().ToArray();
            var s = seq.ReadIntegerBytes().ToArray();
            reader.ThrowIfNotEmpty();

            var raw = new byte[coordSize * 2];
            // copy with left padding
            Buffer.BlockCopy(r, 0, raw, coordSize - r.Length, r.Length);
            Buffer.BlockCopy(s, 0, raw, 2 * coordSize - s.Length, s.Length);
            return raw;
        }
        // Convert raw r||s -> DER encoded signature
        private static byte[] RawToDer(byte[] rawSig, int coordSize)
        {
            if (rawSig.Length != coordSize * 2)
                throw new ArgumentException("rawSig length invalid for coordinate size");

            var r = new ReadOnlySpan<byte>(rawSig, 0, coordSize);
            var s = new ReadOnlySpan<byte>(rawSig, coordSize, coordSize);

            var writer = new AsnWriter(AsnEncodingRules.DER);
            writer.PushSequence();
            writer.WriteIntegerUnsigned(r.ToArray()); // ensures unsigned INTEGER (strips leading zeros)
            writer.WriteIntegerUnsigned(s.ToArray());
            writer.PopSequence();
            return writer.Encode();
        }
    }
}
