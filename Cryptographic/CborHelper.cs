using System.Formats.Cbor;
using System.Security.Cryptography;

namespace WebAuthn_Client_.NET.Cryptographic
{
    // CBOR Utilities for proper WebAuthn compliance
    public static class CborHelper
    {
        public static byte[] EncodeAttestationObject(byte[] authenticatorData)
        {
            string format = "none";
            var writer = new CborWriter();

            // Write attestation object as a map with 3 entries
            writer.WriteStartMap(3);

            // fmt (format)
            writer.WriteTextString("fmt");
            writer.WriteTextString(format);

            // attStmt (attestation statement) - empty map for "none" format
            writer.WriteTextString("attStmt");
            writer.WriteStartMap(0);
            writer.WriteEndMap();

            // authData (authenticator data)
            writer.WriteTextString("authData");
            writer.WriteByteString(authenticatorData);

            writer.WriteEndMap();

            return writer.Encode();
        }

        public static byte[] EncodeCoseKey(string publicKey, CoseAlgorithm algorithm)
        {
            var writer = new CborWriter();

            if (algorithm == CoseAlgorithm.ES256)
            {
                writer.WriteStartMap(5); // 5 entries: kty, alg, crv, x, y

                // Key type (kty)
                writer.WriteInt32(1);
                writer.WriteInt32(2); // EC2 key type

                // Algorithm (alg)
                writer.WriteInt32(3);
                writer.WriteInt32((int)algorithm);

                using (var ecdsa = ECDsa.Create())
                {
                    ecdsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKey), out _);
                    var parameters = ecdsa.ExportParameters(false);

                    // Curve (crv)
                    writer.WriteInt32(-1);
                    writer.WriteInt32(1); // P-256

                    // x coordinate
                    writer.WriteInt32(-2);
                    writer.WriteByteString(parameters.Q.X!);

                    // y coordinate
                    writer.WriteInt32(-3);
                    writer.WriteByteString(parameters.Q.Y!);
                }

                writer.WriteEndMap();
            }
            else if (algorithm == CoseAlgorithm.RS256)
            {
                writer.WriteStartMap(4); // 4 entries: kty, alg, n, e

                // Key type (kty)
                writer.WriteInt32(1);
                writer.WriteInt32(3); // RSA key type

                // Algorithm (alg)
                writer.WriteInt32(3);
                writer.WriteInt32((int)algorithm);

                using (var rsa = RSA.Create())
                {
                    rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKey), out _);
                    var parameters = rsa.ExportParameters(false);

                    // n (modulus)
                    writer.WriteInt32(-1);
                    writer.WriteByteString(parameters.Modulus!);

                    // e (exponent)
                    writer.WriteInt32(-2);
                    writer.WriteByteString(parameters.Exponent!);
                }

                writer.WriteEndMap();
            }

            return writer.Encode();
        }

        public static Dictionary<string, object> DecodeAttestationObject(byte[] cborData)
        {
            var reader = new CborReader(cborData);
            var result = new Dictionary<string, object>();

            reader.ReadStartMap();

            while (reader.PeekState() != CborReaderState.EndMap)
            {
                var key = reader.ReadTextString();

                switch (key)
                {
                    case "fmt":
                        result[key] = reader.ReadTextString();
                        break;
                    case "attStmt":
                        // Skip the attestation statement map for now
                        reader.ReadStartMap();
                        while (reader.PeekState() != CborReaderState.EndMap)
                        {
                            reader.SkipValue(); // key
                            reader.SkipValue(); // value
                        }
                        reader.ReadEndMap();
                        result[key] = new Dictionary<string, object>();
                        break;
                    case "authData":
                        result[key] = reader.ReadByteString();
                        break;
                    default:
                        reader.SkipValue();
                        break;
                }
            }

            reader.ReadEndMap();
            return result;
        }
    }
}
