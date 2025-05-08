using System.Text.Json.Serialization;

namespace AspCoreApiWithJWT.Models.Responses
{

    public class AuthResponse
    {
        public int Id { get; set; }
        public string UserName { get; set; }
        public string Email { get; set; }
        public string Token { get; set; }

        [JsonPropertyName("refresh_token_expires_in")]
        public DateTime Expires { get; set; }

        [JsonIgnore]
        public string RefreshToken { get; set; }
    }

}
