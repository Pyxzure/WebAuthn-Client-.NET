using System.Formats.Cbor;

namespace WebAuthn_Client_.NET.Cryptographic
{
    // CBOR Utilities for proper WebAuthn compliance
    public static class CborHelper
    {
        public static byte[] EncodeAttestationObject(byte[] authenticatorData, string format = "none")
        {
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

            // COSE Key is a CBOR map
            writer.WriteStartMap(null); // Unknown number of entries initially

            // Key type (kty)
            writer.WriteInt32(1); // kty label
            switch (algorithm)
            {
                case CoseAlgorithm.ES256:
                    writer.WriteInt32(2); // EC2 key type
                    break;
                case CoseAlgorithm.RS256:
                    writer.WriteInt32(3); // RSA key type
                    break;
                default:
                    throw new NotSupportedException($"Algorithm {algorithm} not supported for COSE key encoding");
            }

            // Algorithm identifier (alg)
            writer.WriteInt32(3); // alg label
            writer.WriteInt32((int)algorithm);

            if (algorithm == CoseAlgorithm.ES256)
            {
                // For EC2 keys, we need to extract x and y coordinates
                var keyBytes = Convert.FromBase64String(publicKey);

                // Curve identifier (crv)
                writer.WriteInt32(-1); // crv label
                writer.WriteInt32(1);  // P-256 curve

                // Extract coordinates from the public key
                // This is a simplified extraction - real implementation would parse the DER structure
                var coordinateSize = 32; // P-256 coordinate size
                if (keyBytes.Length >= coordinateSize * 2)
                {
                    // x coordinate
                    writer.WriteInt32(-2); // x label
                    writer.WriteByteString(keyBytes.Skip(keyBytes.Length - coordinateSize * 2).Take(coordinateSize).ToArray());

                    // y coordinate
                    writer.WriteInt32(-3); // y label
                    writer.WriteByteString(keyBytes.Skip(keyBytes.Length - coordinateSize).Take(coordinateSize).ToArray());
                }
            }
            else if (algorithm == CoseAlgorithm.RS256)
            {
                // For RSA keys, we need n and e parameters
                // This is a simplified implementation
                var keyBytes = Convert.FromBase64String(publicKey);

                // n (modulus) - simplified extraction
                writer.WriteInt32(-1); // n label
                writer.WriteByteString(keyBytes.Take(256).ToArray()); // Simplified

                // e (exponent) - typically 65537
                writer.WriteInt32(-2); // e label
                writer.WriteByteString(new byte[] { 0x01, 0x00, 0x01 }); // Common exponent 65537
            }

            writer.WriteEndMap();
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
