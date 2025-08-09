using System.Text;

namespace WebAuthn_Client_.NET
{
    public static class Base64UrlHelper
    {
        public static string Encode(byte[] input)
        {
            var base64 = Convert.ToBase64String(input);
            return base64.TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        public static byte[] Decode(string input)
        {
            var base64 = input.Replace('-', '+').Replace('_', '/');
            switch (base64.Length % 4)
            {
                case 2: base64 += "=="; break;
                case 3: base64 += "="; break;
            }
            return Convert.FromBase64String(base64);
        }

        public static string EncodeString(string input)
        {
            return Encode(Encoding.UTF8.GetBytes(input));
        }

        public static string DecodeString(string input)
        {
            return Encoding.UTF8.GetString(Decode(input));
        }
    }
}
