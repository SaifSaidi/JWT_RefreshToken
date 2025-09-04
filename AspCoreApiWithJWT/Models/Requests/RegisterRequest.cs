using System.ComponentModel.DataAnnotations;

namespace AspCoreApiWithJWT.Models.Requests
{
    public class RegisterRequest
    {
        [Required, StringLength(255)]
        public string UserName { get; set; } = string.Empty;
        [Required, StringLength(255), EmailAddress]
        public string Email { get; set; } = string.Empty;
        [Required, StringLength(255)]
        public string Password { get; set; } = string.Empty;

        public Roles Role { get; set; } = Roles.User;
    }

}
