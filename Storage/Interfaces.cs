namespace WebAuthn_Client_.NET.Storage
{
    // Storage model for CSV persistence
    public class CredentialRecord
    {
        public required string CredentialId { get; set; }
        public required string UserId { get; set; }
        public required string UserName { get; set; }
        public required string RpId { get; set; }
        public required string Algorithm { get; set; }
        public required string PublicKey { get; set; }
        public required string PrivateKey { get; set; }
        public int SignCount { get; set; }
        public DateTime CreatedAt { get; set; }
    }
    public interface ICredentialStorage
    {
        // Optional encryptor/decryptor for private key data
        Func<string, string>? Encryptor { get; set; }
        Func<string, string>? Decryptor { get; set; }
        // Save a credential record to storage
        void SaveCredential(CredentialRecord credential);
        CredentialRecord? GetCredential(string credentialId);
        List<CredentialRecord> GetCredentialsByUser(string userId);
        List<CredentialRecord> GetCredentialsByRp(string rpId);
        void UpdateSignCount(string credentialId, int newCount);
        List<CredentialRecord> GetAllCredentials();
    }
}
