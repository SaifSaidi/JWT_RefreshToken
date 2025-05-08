using System.ComponentModel.DataAnnotations;

namespace AspCoreApiWithJWT.Models.Requests
{
    public class RegisterRequest
    {
        [Required, StringLength(255)]
        public string UserName { get; set; }
        [Required, StringLength(255), EmailAddress]
        public string Email { get; set; }
        [Required, StringLength(255)]
        public string Password { get; set; }

        public Roles Role { get; set; } = Roles.User;
    }

}
