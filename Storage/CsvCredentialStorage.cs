using System.Text;

namespace WebAuthn_Client_.NET.Storage
{
    public class CsvCredentialStorage : ICredentialStorage
    {
        public Func<string, string>? Encryptor { get; set; }
        public Func<string, string>? Decryptor { get; set; }
        private readonly string _filePath;
        private readonly object _lockObject = new object();

        public CsvCredentialStorage(string filePath = "credentials.csv")
        {
            Encryptor = s => s; // Default no-op encryptor
            Decryptor = s => s; // Default no-op decryptor
            _filePath = filePath;
            InitializeCsvFile();
        }

        private void InitializeCsvFile()
        {
            if (!File.Exists(_filePath))
            {
                var header = "CredentialId,UserId,UserName,RpId,Algorithm,PublicKey,PrivateKey,SignCount,CreatedAt";
                File.WriteAllText(_filePath, header + Environment.NewLine);
            }
        }

        public void SaveCredential(CredentialRecord credential)
        {
            lock (_lockObject)
            {
                var csvLine = $"{EscapeCsv(credential.CredentialId)}," +
                             $"{EscapeCsv(credential.UserId)}," +
                             $"{EscapeCsv(credential.UserName)}," +
                             $"{EscapeCsv(credential.RpId)}," +
                             $"{EscapeCsv(credential.Algorithm)}," +
                             $"{EscapeCsv(credential.PublicKey)}," +
                             $"{EscapeCsv(Encryptor!(credential.PrivateKey))}," +
                             $"{credential.SignCount}," +
                             $"{credential.CreatedAt:yyyy-MM-ddTHH:mm:ss.fffZ}";

                File.AppendAllText(_filePath, csvLine + Environment.NewLine);
            }
        }

        public CredentialRecord? GetCredential(string credentialId)
        {
            var credentials = GetAllCredentials();
            return credentials.FirstOrDefault(c => c.CredentialId == credentialId);
        }

        public List<CredentialRecord> GetCredentialsByUser(string userId)
        {
            var credentials = GetAllCredentials();
            return credentials.Where(c => c.UserId == userId).ToList();
        }
        public List<CredentialRecord> GetCredentialsByRp(string rpId)
        {
            var credentials = GetAllCredentials();
            return credentials.Where(c => c.RpId == rpId).ToList();
        }

        public void UpdateSignCount(string credentialId, int newCount)
        {
            lock (_lockObject)
            {
                var credentials = GetAllCredentials();
                var credential = credentials.FirstOrDefault(c => c.CredentialId == credentialId);
                if (credential != null)
                {
                    credential.SignCount = newCount;
                    RewriteCsvFile(credentials);
                }
            }
        }

        public List<CredentialRecord> GetAllCredentials()
        {
            lock (_lockObject)
            {
                var credentials = new List<CredentialRecord>();
                if (!File.Exists(_filePath)) return credentials;

                var lines = File.ReadAllLines(_filePath);
                for (int i = 1; i < lines.Length; i++) // Skip header
                {
                    var fields = ParseCsvLine(lines[i]);
                    if (fields.Length >= 9)
                    {
                        credentials.Add(new CredentialRecord
                        {
                            CredentialId = fields[0],
                            UserId = fields[1],
                            UserName = fields[2],
                            RpId = fields[3],
                            Algorithm = fields[4],
                            PublicKey = fields[5],
                            PrivateKey = Decryptor!(fields[6]),
                            SignCount = int.Parse(fields[7]),
                            CreatedAt = DateTime.Parse(fields[8])
                        });
                    }
                }
                return credentials;
            }
        }

        private void RewriteCsvFile(List<CredentialRecord> credentials)
        {
            var lines = new List<string>
            {
                "CredentialId,UserId,UserName,RpId,Algorithm,PublicKey,PrivateKey,SignCount,CreatedAt"
            };

            foreach (var cred in credentials)
            {
                lines.Add($"{EscapeCsv(cred.CredentialId)}," +
                         $"{EscapeCsv(cred.UserId)}," +
                         $"{EscapeCsv(cred.UserName)}," +
                         $"{EscapeCsv(cred.RpId)}," +
                         $"{EscapeCsv(cred.Algorithm)}," +
                         $"{EscapeCsv(cred.PublicKey)}," +
                         $"{EscapeCsv(Encryptor!(cred.PrivateKey))}," +
                         $"{cred.SignCount}," +
                         $"{cred.CreatedAt:yyyy-MM-ddTHH:mm:ss.fffZ}");
            }

            File.WriteAllLines(_filePath, lines);
        }

        private static string EscapeCsv(string value)
        {
            if (string.IsNullOrEmpty(value)) return "";
            if (value.Contains(',') || value.Contains('"') || value.Contains('\n'))
            {
                return "\"" + value.Replace("\"", "\"\"") + "\"";
            }
            return value;
        }

        private static string[] ParseCsvLine(string line)
        {
            var fields = new List<string>();
            var inQuotes = false;
            var currentField = new StringBuilder();

            for (int i = 0; i < line.Length; i++)
            {
                if (line[i] == '"')
                {
                    if (inQuotes && i + 1 < line.Length && line[i + 1] == '"')
                    {
                        currentField.Append('"');
                        i++; // Skip next quote
                    }
                    else
                    {
                        inQuotes = !inQuotes;
                    }
                }
                else if (line[i] == ',' && !inQuotes)
                {
                    fields.Add(currentField.ToString());
                    currentField.Clear();
                }
                else
                {
                    currentField.Append(line[i]);
                }
            }

            fields.Add(currentField.ToString());
            return fields.ToArray();
        }
    }
}
