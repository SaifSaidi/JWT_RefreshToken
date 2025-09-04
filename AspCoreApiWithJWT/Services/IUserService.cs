using AspCoreApiWithJWT.Models;
using AspCoreApiWithJWT.Models.Requests;
using AspCoreApiWithJWT.Models.Responses;

namespace AspCoreApiWithJWT.Services
{
    public interface IUserService
    {
        Task<AuthResponse?> Authenticate(AuthRequest model, string ipAddress);
        Task<AuthResponse> Register(RegisterRequest model, string ipAddress);
        Task<AuthResponse> RefreshToken(string token, string ipAddress);
        Task RevokeToken(string token, string ipAddress);
        Task<User?> GetById(int id);
        Task<IEnumerable<User>> GetAll();
    }


}
