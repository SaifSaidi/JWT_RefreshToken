using System.Text.Json.Serialization;

namespace AspCoreApiWithJWT.Models
{
    public class User
    {
        public int Id { get; set; }
        public string UserName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;

        [JsonIgnore]
        public string PasswordHash { get; set; } = string.Empty;

        public Roles Role { get; set; } = Roles.User;
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        [JsonIgnore]
        public List<RefreshToken> RefreshTokens { get; set; } = [];
    }

}
