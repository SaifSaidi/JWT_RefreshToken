using System.ComponentModel.DataAnnotations;

namespace AspCoreApiWithJWT.Models.Requests
{
    public class AuthRequest
    {
        [Required, StringLength(255)]
        public string UserName { get; set; }
        [Required, StringLength(255)]
        public string Password { get; set; }
    }


}
