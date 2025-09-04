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
        private readonly ILogger<UserService> _logger;

        public UserService(ApplicationDbContext context, ITokenService tokenService, ILogger<UserService> logger)
        {
            _context = context;
            _tokenService = tokenService;
            _logger = logger;
        }

        // Login/Authenticate user
        public async Task<AuthResponse?> Authenticate(AuthRequest model, string ipAddress)
        {
            var user = await _context.Users
                .Include(u => u.RefreshTokens)
                .SingleOrDefaultAsync(x => x.UserName == model.UserName);

            // Return null if user not found or password is incorrect
            if (user == null || !VerifyPassword(model.Password, user.PasswordHash))
                return null;

            // Authentication successful, generate tokens
            var authResponse = await GenerateAuthResponse(user, ipAddress);
            return authResponse;
        }

        public async Task<AuthResponse> Register(RegisterRequest model, string ipAddress)
        {
            // Check if username already exists
            if (await _context.Users.AnyAsync(x => x.UserName == model.UserName))
                throw new BadHttpRequestException($"Username '{model.UserName}' is already taken");

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
            var authResponse = await GenerateAuthResponse(user, ipAddress);
            return authResponse;
        }

        public async Task<AuthResponse> RefreshToken(string token, string ipAddress)
        {
            var user = await GetUserByRefreshToken(token);

            if (user == null)
                throw new KeyNotFoundException("Invalid token");

            var refreshToken = user.RefreshTokens.Single(x => x.Token == token);

            if (!refreshToken.IsActive)
                throw new BadHttpRequestException("Invalid token");

            // Generate new auth response
            var authResponse = await GenerateAuthResponse(user, ipAddress, refreshToken);
            return authResponse;
        }

        public async Task RevokeToken(string token, string ipAddress)
        {
            var user = await GetUserByRefreshToken(token);

            if (user == null)
            {
                _logger.LogWarning("User not found for token");
                throw new KeyNotFoundException("Invalid token");
            }

            var refreshToken = user.RefreshTokens.Single(x => x.Token == token);

            if (!refreshToken.IsActive)
                throw new BadHttpRequestException("Invalid token");

            // Revoke token
            refreshToken.Revoked = DateTime.UtcNow;
            refreshToken.RevokedByIp = ipAddress;
            refreshToken.ReasonRevoked = "Revoked without replacement";

            await _context.SaveChangesAsync();
        }

        public async Task<User?> GetById(int id)
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
        private async Task<User?> GetUserByRefreshToken(string token)
        {
            return await _context.Users
                .Include(u => u.RefreshTokens)
                .SingleOrDefaultAsync(u => u.RefreshTokens.Any(t => t.Token == token));
        }

        private void RemoveOldRefreshTokens(User user)
        {
            int count = user.RefreshTokens.RemoveAll(x => x.Expires <= DateTime.UtcNow);
            _logger.LogInformation($"Removed {count} old refresh tokens for user {user.UserName}");
        }

        private static bool VerifyPassword(string password, string storedHash)
        {
            var hash = HashPassword.Hash(password);
            return hash == storedHash;
        }

        private async Task<AuthResponse> GenerateAuthResponse(User user, string ipAddress, RefreshToken? currentRefreshToken = null)
        {
            var jwtToken = _tokenService.GenerateJwtToken(user);
            var newRefreshToken = _tokenService.GenerateRefreshToken(ipAddress);

            if (currentRefreshToken != null)
            {
                // Revoke the current refresh token
                currentRefreshToken.Revoked = DateTime.UtcNow;
                currentRefreshToken.RevokedByIp = ipAddress;
                currentRefreshToken.ReplacedByToken = newRefreshToken.Token;
            }

            // Add the new refresh token
            user.RefreshTokens.Add(newRefreshToken);

            // Remove old refresh tokens
            RemoveOldRefreshTokens(user);

            // Save changes
            await _context.SaveChangesAsync();

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
    }
}
