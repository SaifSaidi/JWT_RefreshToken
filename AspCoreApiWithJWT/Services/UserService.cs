using System.Security.Claims;
using System.Text;
using AspCoreApiWithJWT.Data;
using AspCoreApiWithJWT.Helpers;
using AspCoreApiWithJWT.Models;
using AspCoreApiWithJWT.Models.Requests;
using AspCoreApiWithJWT.Models.Responses;
using Microsoft.EntityFrameworkCore;

namespace AspCoreApiWithJWT.Services
{
    public class UserService : IUserService
    {
        private readonly ApplicationDbContext _context;
        private readonly ITokenService _tokenService;

        public UserService(ApplicationDbContext context, ITokenService tokenService)
        {
            _context = context;
            _tokenService = tokenService;
        }

        // Login/Authenticate user
        public async Task<AuthResponse> Authenticate(AuthRequest model, string ipAddress)
        {
            var user = await _context.Users
                .Include(u => u.RefreshTokens)
                .SingleOrDefaultAsync(x => x.UserName == model.UserName);

            // Return null if user not found
            if (user == null) return null;

            // Verify password
            if (!VerifyPassword(model.Password, user.PasswordHash))
                return null;

            // Authentication successful, generate tokens
            var jwtToken = _tokenService.GenerateJwtToken(user);
            var refreshToken = _tokenService.GenerateRefreshToken(ipAddress);

            // Save refresh token
            user.RefreshTokens.Add(refreshToken);

            // Remove old refresh tokens
            RemoveOldRefreshTokens(user);

            await _context.SaveChangesAsync();

            return new AuthResponse
            {
                Id = user.Id,
                UserName = user.UserName,
                Email = user.Email,
                Token = jwtToken,
                RefreshToken = refreshToken.Token,
                Expires = refreshToken.Expires.ToLocalTime()
            };
        }

        public async Task<AuthResponse> Register(RegisterRequest model, string ipAddress)
        {
            // Check if username already exists
            if (await _context.Users.AnyAsync(x => x.UserName == model.UserName))
                throw new Exception("Username '" + model.UserName + "' is already taken");

            // Create user
            var user = new User
            {
                UserName = model.UserName,
                Email = model.Email,
                PasswordHash = HashPassword.Hash(model.Password),
                Role = model.Role,
            };

            // Save user
            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            // Generate tokens
            var jwtToken = _tokenService.GenerateJwtToken(user);
            var refreshToken = _tokenService.GenerateRefreshToken(ipAddress);

            // Save refresh token
            user.RefreshTokens.Add(refreshToken);
            await _context.SaveChangesAsync();

            return new AuthResponse
            {
                Id = user.Id,
                UserName = user.UserName,
                Email = user.Email,
                Token = jwtToken,
                RefreshToken = refreshToken.Token,
                Expires = refreshToken.Expires.ToLocalTime()
            };
        }

        public async Task<AuthResponse> RefreshToken(string token, string ipAddress)
        {
            var user = await GetUserByRefreshToken(token);

            if (user == null)
                throw new Exception("Invalid token");

            var refreshToken = user.RefreshTokens.Single(x => x.Token == token);

            if (!refreshToken.IsActive)
                throw new Exception("Invalid token");

            // Generate new refresh token
            var newRefreshToken = _tokenService.GenerateRefreshToken(ipAddress);

            // Revoke the current refresh token
            refreshToken.Revoked = DateTime.UtcNow;
            refreshToken.RevokedByIp = ipAddress;
            refreshToken.ReplacedByToken = newRefreshToken.Token;

            // Add the new refresh token
            user.RefreshTokens.Add(newRefreshToken);

            // Remove old refresh tokens
            RemoveOldRefreshTokens(user);

            // Save changes
            await _context.SaveChangesAsync();

            // Generate new jwt token
            var jwtToken = _tokenService.GenerateJwtToken(user);

            return new AuthResponse
            {
                Id = user.Id,
                UserName = user.UserName,
                Email = user.Email,
                Token = jwtToken,
                RefreshToken = newRefreshToken.Token,
                Expires = newRefreshToken.Expires
            };
        }

        public async Task RevokeToken(string token, string ipAddress)
        {
            var user = await GetUserByRefreshToken(token);

            if (user == null)

            {
                Console.WriteLine("User not found");
                throw new Exception("Invalid token");
            }
            var refreshToken = user.RefreshTokens.Single(x => x.Token == token);

            Console.WriteLine(refreshToken.IsActive);
            if (!refreshToken.IsActive)
                throw new Exception("Invalid token");

            // Revoke token
            refreshToken.Revoked = DateTime.UtcNow;
            refreshToken.RevokedByIp = ipAddress;
            refreshToken.ReasonRevoked = "Revoked without replacement";

            await _context.SaveChangesAsync();
        }

        public async Task<User> GetById(int id)
        {
            return await _context.Users
                .Include(u => u.RefreshTokens)
                .FirstOrDefaultAsync(u => u.Id == id);
        }

        public async Task<IEnumerable<User>> GetAll()
        {
            return await _context.Users.ToListAsync();
        }

        // Helper methods
        private async Task<User> GetUserByRefreshToken(string token)
        {
            return await _context.Users
                .Include(u => u.RefreshTokens)
                .SingleOrDefaultAsync(u => u.RefreshTokens.Any(t => t.Token == token));
        }

        private static void RemoveOldRefreshTokens(User user)
        {
          int count =  user.RefreshTokens.RemoveAll(x =>
                !x.IsActive &&
                x.Created <= DateTime.UtcNow);

            Console.WriteLine($"Removed {count} old refresh tokens for user {user.UserName}");
        } 

        private static bool VerifyPassword(string password, string storedHash)
        {
            var hash = HashPassword.Hash(password);
            return hash == storedHash;
        }
    }


}
