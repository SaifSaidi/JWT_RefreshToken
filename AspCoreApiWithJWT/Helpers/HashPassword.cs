using System.Security.Cryptography;
using System.Text;

namespace AspCoreApiWithJWT.Helpers
{
    public static class HashPassword
    {
        public static string Hash(string password)
        {
            using var sha256 = SHA256.Create();
            var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
            return BitConverter.ToString(hashedBytes).Replace("-", "").ToLower();
        }
    }
}
