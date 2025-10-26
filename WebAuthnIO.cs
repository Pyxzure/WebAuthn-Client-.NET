using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace WebAuthnClient
{
    public class WebAuthnIO
    {
        private readonly string _sessionId;
        private static readonly HttpClient _httpClient = new HttpClient();

        public WebAuthnIO(string sessionId)
        {
            _sessionId = sessionId;
        }

        public static async Task<WebAuthnIO> CreateAsync()
        {
            var sessionId = await GetSessionIdAsync();
            return new WebAuthnIO(sessionId);
        }

        public PasskeysUser GetUser()
        {
            return new PasskeysUser
            {
                Username = $"user-{_sessionId}",
                Id = _sessionId
            };
        }

        /// <summary>
        /// Get a passkey registration options by https://webauthn.io/registration/options
        /// </summary>
        public async Task<string> GetRegistrationOptionsAsync(PasskeysUser user)
        {
            var optionsRequest = new
            {
                username = user.Username,
                user_verification = "preferred",
                attestation = "none",
                attachment = "all",
                algorithms = new[] { "es256", "rs256" },
                discoverable_credential = "preferred",
                hints = Array.Empty<string>()
            };

            var json = JsonSerializer.Serialize(optionsRequest);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var response = await _httpClient.PostAsync("https://webauthn.io/registration/options", content);
            response.EnsureSuccessStatusCode();

            var responseJson = await response.Content.ReadAsStringAsync();
            return responseJson;
        }

        /// <summary>
        /// Register your passkey account by https://webauthn.io/registration/verification
        /// </summary>
        public async Task GetRegistrationVerificationAsync(PasskeysUser user, string response)
        {
            //var verificationRequest = new
            //{
            //    response = response,
            //    username = user.Username
            //};

            // var json = JsonSerializer.Serialize(verificationRequest);
            string json = $"{{\"response\":{response}, \"username\": \"{user.Username}\"}}";
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var httpResponse = await _httpClient.PostAsync("https://webauthn.io/registration/verification", content);
            string retStr = await httpResponse.Content.ReadAsStringAsync();
            httpResponse.EnsureSuccessStatusCode();

            var responseJson = await httpResponse.Content.ReadAsStringAsync();
            var verificationResult = JsonSerializer.Deserialize<VerificationResult>(responseJson);

            if (verificationResult?.Verified != true)
            {
                throw new Exception($"Verification failed: {responseJson}");
            }
        }

        /// <summary>
        /// Get a passkey authentication options by https://webauthn.io/authentication/options
        /// </summary>
        public async Task<string> GetAuthenticationOptionsAsync()
        {
            var optionsRequest = new
            {
                user_verification = "preferred"
            };

            var json = JsonSerializer.Serialize(optionsRequest);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var request = new HttpRequestMessage(HttpMethod.Post, "https://webauthn.io/authentication/options")
            {
                Content = content
            };
            request.Headers.Add("Cookie", $"sessionid={_sessionId}");

            var response = await _httpClient.SendAsync(request);
            response.EnsureSuccessStatusCode();

            var responseJson = await response.Content.ReadAsStringAsync();
            return responseJson;
            //return JsonSerializer.Deserialize<PublicKeyCredentialRequestOptionsJSON>(responseJson)!;
        }

        /// <summary>
        /// Authenticate your passkey account by https://webauthn.io/authentication/verification
        /// </summary>
        public async Task GetAuthenticationVerificationAsync(AuthenticationResponseJSON response)
        {
            var verificationRequest = new
            {
                response = response,
                username = ""
            };

            var json = JsonSerializer.Serialize(verificationRequest);
            //string json = $"{{\"response\":{response}, \"username\": \"\"}}";
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var request = new HttpRequestMessage(HttpMethod.Post, "https://webauthn.io/authentication/verification")
            {
                Content = content
            };
            request.Headers.Add("Cookie", $"sessionid={_sessionId}");

            var httpResponse = await _httpClient.SendAsync(request);
            httpResponse.EnsureSuccessStatusCode();

            var responseJson = await httpResponse.Content.ReadAsStringAsync();
            var verificationResult = JsonSerializer.Deserialize<VerificationResult>(responseJson);

            if (verificationResult?.Verified != true)
            {
                throw new Exception($"Verification failed: {responseJson}");
            }
        }

        private static async Task<string> GetSessionIdAsync()
        {
            var response = await _httpClient.GetAsync("https://webauthn.io/");
            response.EnsureSuccessStatusCode();

            if (response.Headers.TryGetValues("Set-Cookie", out var cookies))
            {
                var sessionCookie = cookies.FirstOrDefault(c => c.StartsWith("sessionid="));
                if (sessionCookie != null)
                {
                    return sessionCookie.Split(';')[0].Split('=')[1];
                }
            }

            return string.Empty;
        }
    }

    // Supporting classes
    public class PasskeysUser
    {
        [JsonPropertyName("username")]
        public required string Username { get; set; }

        [JsonPropertyName("id")]
        public required string Id { get; set; }
    }

    public class PublicKeyCredentialCreationOptionsJSON
    {
        // Add properties based on WebAuthn spec
        [JsonPropertyName("challenge")]
        public required string Challenge { get; set; }

        [JsonPropertyName("rp")]
        public required object Rp { get; set; }

        [JsonPropertyName("user")]
        public required object User { get; set; }

        [JsonPropertyName("pubKeyCredParams")]
        public required object[] PubKeyCredParams { get; set; }
    }

    public class RegistrationResponseJSON
    {
        // Add properties based on your registration response structure
        [JsonPropertyName("id")]
        public required string Id { get; set; }

        [JsonPropertyName("rawId")]
        public required string RawId { get; set; }

        [JsonPropertyName("response")]
        public required object Response { get; set; }

        [JsonPropertyName("type")]
        public required string Type { get; set; }
    }

    public class PublicKeyCredentialRequestOptionsJSON
    {
        // Add properties based on WebAuthn spec
        [JsonPropertyName("challenge")]
        public required string Challenge { get; set; }

        [JsonPropertyName("timeout")]
        public int? Timeout { get; set; }

        [JsonPropertyName("rpId")]
        public required string RpId { get; set; }

        [JsonPropertyName("allowCredentials")]
        public required object[] AllowCredentials { get; set; }
    }

    public class AuthenticationResponseJSON
    {
        // Add properties based on your authentication response structure
        [JsonPropertyName("id")]
        public required string Id { get; set; }

        [JsonPropertyName("rawId")]
        public required string RawId { get; set; }

        [JsonPropertyName("response")]
        public required object Response { get; set; }

        [JsonPropertyName("type")]
        public required string Type { get; set; }
    }

    public class VerificationResult
    {
        [JsonPropertyName("verified")]
        public bool Verified { get; set; }
    }
}
