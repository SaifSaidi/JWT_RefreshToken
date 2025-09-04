using System.Security.Claims;
using AspCoreApiWithJWT.Models;

namespace AspCoreApiWithJWT.Services
{
    public interface ITokenService
    {
        string GenerateJwtToken(User user);
        RefreshToken GenerateRefreshToken(string ipAddress);
    }

}