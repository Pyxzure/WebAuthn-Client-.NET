using System.Text.Json.Serialization;

namespace WebAuthn_Client_.NET
{
    public class PublicKeyCredentialCreationOptions
    {
        [JsonPropertyName("rp")]
        public required RelyingParty Rp { get; set; }

        [JsonPropertyName("user")]
        public required User User { get; set; }

        [JsonPropertyName("challenge")]
        public required string Challenge { get; set; }

        [JsonPropertyName("pubKeyCredParams")]
        public required List<PublicKeyCredentialParameters> PubKeyCredParams { get; set; }

        [JsonPropertyName("timeout")]
        public double? Timeout { get; set; }

        [JsonPropertyName("excludeCredentials")]
        public List<PublicKeyCredentialDescriptor>? ExcludeCredentials { get; set; }

        [JsonPropertyName("authenticatorSelection")]
        public AuthenticatorSelectionCriteria? AuthenticatorSelection { get; set; }

        [JsonPropertyName("attestation")]
        public string Attestation { get; set; } = "none";
    }

    public class PublicKeyCredentialRequestOptions
    {
        [JsonPropertyName("challenge")]
        public required string Challenge { get; set; }

        [JsonPropertyName("timeout")]
        public uint? Timeout { get; set; }

        [JsonPropertyName("rpId")]
        public required string RpId { get; set; }

        [JsonPropertyName("allowCredentials")]
        public List<PublicKeyCredentialDescriptor>? AllowCredentials { get; set; }

        [JsonPropertyName("userVerification")]
        public string UserVerification { get; set; } = "preferred";
    }

    public class RelyingParty
    {
        [JsonPropertyName("id")]
        public required string Id { get; set; }

        [JsonPropertyName("name")]
        public required string Name { get; set; }
    }

    public class User
    {
        [JsonPropertyName("id")]
        public required string Id { get; set; }

        [JsonPropertyName("name")]
        public required string Name { get; set; }

        [JsonPropertyName("displayName")]
        public required string DisplayName { get; set; }
    }

    public class PublicKeyCredentialParameters
    {
        [JsonPropertyName("type")]
        public string Type { get; set; } = "public-key";

        [JsonPropertyName("alg")]
        public int Alg { get; set; }
    }

    public class PublicKeyCredentialDescriptor
    {
        [JsonPropertyName("type")]
        public string Type { get; set; } = "public-key";

        [JsonPropertyName("id")]
        public required string Id { get; set; }

        [JsonPropertyName("transports")]
        public List<string>? Transports { get; set; }
    }

    public class AuthenticatorSelectionCriteria
    {
        [JsonPropertyName("authenticatorAttachment")]
        public string? AuthenticatorAttachment { get; set; }

        [JsonPropertyName("requireResidentKey")]
        public bool RequireResidentKey { get; set; } = false;

        [JsonPropertyName("residentKey")]
        public string? ResidentKey { get; set; }

        [JsonPropertyName("userVerification")]
        public string UserVerification { get; set; } = "preferred";
    }

    // Response structures
    public class PublicKeyCredential
    {
        [JsonPropertyName("id")]
        public required string Id { get; set; }

        [JsonPropertyName("rawId")]
        public required string RawId { get; set; }

        [JsonPropertyName("type")]
        public string Type { get; set; } = "public-key";

        [JsonPropertyName("response")]
        public required object Response { get; set; }

        [JsonPropertyName("authenticatorAttachment")]
        public required string AuthenticatorAttachment { get; set; }

        [JsonPropertyName("clientExtensionResults")]
        public Dictionary<string, object> ClientExtensionResults { get; set; } = new Dictionary<string, object>();
    }

    public class AuthenticatorAttestationResponse
    {
        [JsonPropertyName("clientDataJSON")]
        public required string ClientDataJSON { get; set; }

        [JsonPropertyName("attestationObject")]
        public required string AttestationObject { get; set; }

        [JsonPropertyName("transports")]
        public List<string> Transports { get; set; } = new List<string> { "internal", "hybrid" };
    }

    public class AuthenticatorAssertionResponse
    {
        [JsonPropertyName("clientDataJSON")]
        public required string ClientDataJSON { get; set; }

        [JsonPropertyName("authenticatorData")]
        public required string AuthenticatorData { get; set; }

        [JsonPropertyName("signature")]
        public required string Signature { get; set; }

        [JsonPropertyName("userHandle")]
        public required string UserHandle { get; set; }
    }

    public class ClientData
    {
        [JsonPropertyName("type")]
        public required string Type { get; set; }

        [JsonPropertyName("challenge")]
        public required string Challenge { get; set; }

        [JsonPropertyName("origin")]
        public required string Origin { get; set; }

        [JsonPropertyName("crossOrigin")]
        public bool CrossOrigin { get; set; } = false;
    }
}
