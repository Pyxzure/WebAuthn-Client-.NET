using System.Text;
using System.Text.Json;
using System.Security.Cryptography;
using WebAuthn_Client_.NET.Cryptographic;
using WebAuthn_Client_.NET.Storage;

namespace WebAuthn_Client_.NET
{
    public class FIDOWebAuthn
    {
        private readonly ICredentialStorage _storage;
        private readonly Dictionary<CoseAlgorithm, ICryptographicProvider> _cryptoProviders;
        private readonly Random _random;
        public static readonly byte[] _aaguid = new byte[16]; // Mock AAGUID (all zeros)

        public FIDOWebAuthn(ICredentialStorage? storage = null)
        {
            _storage = storage ?? new CsvCredentialStorage();
            _random = new Random();

            _cryptoProviders = new Dictionary<CoseAlgorithm, ICryptographicProvider>
            {
                // Extend with more cryptographic providers as needed
                { CoseAlgorithm.ES256, new ES256Provider() },
                { CoseAlgorithm.RS256, new RS256Provider() }
            };
        }

        // Create credential (registration)
        public PublicKeyCredential Create(string jsonInput)
        {
            try
            {
                var options = JsonSerializer.Deserialize<PublicKeyCredentialCreationOptions>(jsonInput)!;
                return CreateCredential(options);
            }
            catch (JsonException ex)
            {
                throw new ArgumentException($"Invalid JSON input: {ex.Message}", ex);
            }
        }

        public PublicKeyCredential Create(PublicKeyCredentialCreationOptions options)
        {
            return CreateCredential(options);
        }

        // Get credential (authentication)
        public PublicKeyCredential Get(string jsonInput)
        {
            try
            {
                var options = JsonSerializer.Deserialize<PublicKeyCredentialRequestOptions>(jsonInput)!;
                return GetCredential(options);
            }
            catch (JsonException ex)
            {
                throw new ArgumentException($"Invalid JSON input: {ex.Message}", ex);
            }
        }

        public PublicKeyCredential Get(PublicKeyCredentialRequestOptions options)
        {
            return GetCredential(options);
        }

        private PublicKeyCredential CreateCredential(PublicKeyCredentialCreationOptions options)
        {
            if (options == null)
                throw new ArgumentNullException(nameof(options));

            if (string.IsNullOrEmpty(options.Challenge))
                throw new ArgumentException("Challenge is required");

            if (options.Rp == null || string.IsNullOrEmpty(options.Rp.Id))
                throw new ArgumentException("Relying party information is required");

            if (options.User == null || string.IsNullOrEmpty(options.User.Id))
                throw new ArgumentException("User information is required");

            // Select algorithm
            var algorithm = SelectAlgorithm(options.PubKeyCredParams) ?? throw new NotSupportedException("No supported algorithm found");
            var provider = _cryptoProviders[algorithm];

            // Generate credential ID
            var credentialId = GenerateCredentialId();
            var credentialIdBytes = Convert.FromBase64String(credentialId);

            // Generate key pair
            var (publicKey, privateKey) = provider.GenerateKeyPair();

            // Create and save credential record
            var credentialRecord = new CredentialRecord
            {
                CredentialId = credentialId,
                UserId = options.User.Id,
                UserName = options.User.Name,
                RpId = options.Rp.Id,
                Algorithm = algorithm.ToString(),
                PublicKey = publicKey,
                PrivateKey = privateKey,
                SignCount = 0,
                CreatedAt = DateTime.UtcNow
            };

            _storage.SaveCredential(credentialRecord);

            // Create client data
            var clientData = new ClientData
            {
                Type = "webauthn.create",
                Challenge = options.Challenge,
                Origin = $"https://{options.Rp.Id}",
                CrossOrigin = false
            };

            var clientDataJson = JsonSerializer.Serialize(clientData);
            var clientDataBytes = Encoding.UTF8.GetBytes(clientDataJson);

            // Create COSE public key
            var cosePublicKey = CborHelper.EncodeCoseKey(publicKey, algorithm);

            // Create authenticator data with proper CBOR-encoded credential public key
            var authenticatorData = CreateAuthenticatorData(options.Rp.Id, true, credentialIdBytes, cosePublicKey);

            // Create attestation object using proper CBOR encoding
            var attestationObject = CborHelper.EncodeAttestationObject(authenticatorData, options.Attestation ?? "none");

            // Create response
            var response = new AuthenticatorAttestationResponse
            {
                ClientDataJSON = Base64UrlHelper.Encode(clientDataBytes),
                AttestationObject = Base64UrlHelper.Encode(attestationObject)
            };

            return new PublicKeyCredential
            {
                Id = Base64UrlHelper.Encode(credentialIdBytes),
                RawId = Base64UrlHelper.Encode(credentialIdBytes),
                Response = response,
                AuthenticatorAttachment = "platform"
            };
        }

        private PublicKeyCredential GetCredential(PublicKeyCredentialRequestOptions options)
        {
            if (options == null)
                throw new ArgumentNullException(nameof(options));

            if (string.IsNullOrEmpty(options.Challenge))
                throw new ArgumentException("Challenge is required");

            // Find matching credential
            CredentialRecord? credential = null;

            if (options.AllowCredentials?.Count > 0)
            {
                foreach (var allowedCred in options.AllowCredentials)
                {
                    var credIdBytes = Base64UrlHelper.Decode(allowedCred.Id);
                    var credId = Convert.ToBase64String(credIdBytes);
                    credential = _storage.GetCredential(credId);
                    if (credential != null) break;
                }
            }
            else
            {
                // If no specific credentials are allowed, get the first one
                var credentials = _storage.GetCredentialsByRp(options.RpId);
                if (credentials.Count > 0)
                {
                    credential = credentials[0]; // Just take the first one
                }
            }

            if (credential == null)
                throw new InvalidOperationException("No matching credential found");

            // Verify RP ID matches
            if (!string.IsNullOrEmpty(options.RpId) && credential.RpId != options.RpId)
                throw new UnauthorizedAccessException("RP ID mismatch");

            // Create client data
            var clientData = new ClientData
            {
                Type = "webauthn.get",
                Challenge = options.Challenge,
                Origin = $"https://{credential.RpId}",
                CrossOrigin = false
            };

            var clientDataJson = JsonSerializer.Serialize(clientData);
            var clientDataBytes = Encoding.UTF8.GetBytes(clientDataJson);

            // Create authenticator data (no attested credential data for authentication)
            credential.SignCount++;
            var authenticatorData = CreateAuthenticatorData(credential.RpId, false, null, null, credential.SignCount);

            // Create signature
            var dataToSign = new List<byte>();
            dataToSign.AddRange(authenticatorData);
            dataToSign.AddRange(SHA256.HashData(clientDataBytes));

            var algorithmEnum = Enum.Parse<CoseAlgorithm>(credential.Algorithm);
            var provider = _cryptoProviders[algorithmEnum];
            var signature = provider.Sign(dataToSign.ToArray(), credential.PrivateKey);

            // Update sign count in storage
            _storage.UpdateSignCount(credential.CredentialId, credential.SignCount);

            // Create response
            var response = new AuthenticatorAssertionResponse
            {
                ClientDataJSON = Base64UrlHelper.Encode(clientDataBytes),
                AuthenticatorData = Base64UrlHelper.Encode(authenticatorData),
                Signature = Base64UrlHelper.Encode(signature),
                UserHandle = Base64UrlHelper.EncodeString(credential.UserId)
            };

            var credentialIdBytes = Convert.FromBase64String(credential.CredentialId);
            return new PublicKeyCredential
            {
                Id = Base64UrlHelper.Encode(credentialIdBytes),
                RawId = Base64UrlHelper.Encode(credentialIdBytes),
                Response = response,
                AuthenticatorAttachment = "platform"
            };
        }

        private CoseAlgorithm? SelectAlgorithm(List<PublicKeyCredentialParameters>? pubKeyCredParams)
        {
            if (pubKeyCredParams == null) return CoseAlgorithm.ES256; // Default

            foreach (var param in pubKeyCredParams)
            {
                if (Enum.IsDefined(typeof(CoseAlgorithm), param.Alg))
                {
                    var algorithm = (CoseAlgorithm)param.Alg;
                    if (_cryptoProviders.ContainsKey(algorithm))
                        return algorithm;
                }
            }

            return null;
        }

        private string GenerateCredentialId()
        {
            var bytes = new byte[64];
            _random.NextBytes(bytes);
            return Convert.ToBase64String(bytes);
        }

        private byte[] CreateAuthenticatorData(string rpId, bool includeAttestedCredentialData,
            byte[]? credentialIdBytes = null, byte[]? cosePublicKey = null, int signCount = 0)
        {
            using (var stream = new MemoryStream())
            using (var writer = new BinaryWriter(stream))
            {
                // RP ID hash (32 bytes)
                var rpIdBytes = Encoding.UTF8.GetBytes(rpId);
                var rpIdHash = SHA256.HashData(rpIdBytes);
                writer.Write(rpIdHash);

                // Flags (1 byte)
                byte flags = 0x01; // User present (UP)
                flags |= 0x04; // User present (UP)
                if (includeAttestedCredentialData)
                    flags |= 0x40; // Attested credential data included (AT)
                writer.Write(flags);

                // Signature counter (4 bytes, big-endian)
                var counterBytes = BitConverter.GetBytes((uint)signCount);
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(counterBytes);
                writer.Write(counterBytes);

                // Attested credential data (only for registration)
                if (includeAttestedCredentialData && credentialIdBytes != null && cosePublicKey != null)
                {
                    // AAGUID (16 bytes)
                    writer.Write(_aaguid);

                    // Credential ID length (2 bytes, big-endian)
                    var lengthBytes = BitConverter.GetBytes((ushort)credentialIdBytes.Length);
                    if (BitConverter.IsLittleEndian)
                        Array.Reverse(lengthBytes);
                    writer.Write(lengthBytes);

                    // Credential ID
                    writer.Write(credentialIdBytes);

                    // Credential public key (CBOR-encoded COSE key)
                    writer.Write(cosePublicKey);
                }

                return stream.ToArray();
            }
        }
    }
}
