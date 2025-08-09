using WebAuthn_Client_.NET.Cryptographic;

namespace WebAuthn_Client_.NET
{
    public class Test
    {
        public static void RunExample()
        {
            var authenticator = new FIDOWebAuthn();

            // Registration example
            var createOptions = new PublicKeyCredentialCreationOptions
            {
                Rp = new RelyingParty { Id = "example.com", Name = "Example Corp" },
                User = new User
                {
                    Id = Base64UrlHelper.EncodeString("user123"),
                    Name = "john.doe@example.com",
                    DisplayName = "John Doe"
                },
                Challenge = Base64UrlHelper.EncodeString("random-challenge-123"),
                PubKeyCredParams = new List<PublicKeyCredentialParameters>
                {
                    new PublicKeyCredentialParameters { Alg = -7 }, // ES256
                    new PublicKeyCredentialParameters { Alg = -257 } // RS256
                },
                Attestation = "none"
            };

            var credential = authenticator.Create(createOptions);
            Console.WriteLine($"Created credential: {credential.Id}");

            // Verify the attestation object can be decoded
            var attestationObjectBytes = Base64UrlHelper.Decode(
                ((AuthenticatorAttestationResponse)credential.Response).AttestationObject);
            var decodedAttestation = CborHelper.DecodeAttestationObject(attestationObjectBytes);
            Console.WriteLine($"Attestation format: {decodedAttestation["fmt"]}");

            // Authentication example
            var getOptions = new PublicKeyCredentialRequestOptions
            {
                Challenge = Base64UrlHelper.EncodeString("auth-challenge-456"),
                RpId = "example.com",
                AllowCredentials = new List<PublicKeyCredentialDescriptor>
                {
                    new PublicKeyCredentialDescriptor { Id = credential.Id }
                }
            };

            var assertion = authenticator.Get(getOptions);
            Console.WriteLine($"Authentication successful for credential: {assertion.Id}");
        }
    }
}
