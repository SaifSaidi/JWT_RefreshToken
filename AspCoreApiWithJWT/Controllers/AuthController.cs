using AspCoreApiWithJWT.Models;
using AspCoreApiWithJWT.Models.Requests;
using AspCoreApiWithJWT.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AspCoreApiWithJWT.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IUserService _userService;
        private readonly ILogger<AuthController> _logger;

        public AuthController(IUserService userService, ILogger<AuthController> logger)
        {
            _userService = userService;
            _logger = logger;
        }

        [HttpPost("Login")]
        public async Task<IActionResult> Login(AuthRequest model)
        {
            var ipAddress = GetIpAddress();
            var response = await _userService.Authenticate(model, ipAddress);

            if (response == null)
                return BadRequest(new { message = "Username or password is incorrect" });

            if (response.RefreshToken != null)
            {
                SetRefreshTokenCookie(response.RefreshToken, response.Expires);
            }

            return Ok(response);
        }

        [HttpPost("Register")]
        public async Task<IActionResult> Register(RegisterRequest model)
        {
            var ipAddress = GetIpAddress();
            var response = await _userService.Register(model, ipAddress);

            if (response.RefreshToken != null)
            {
                SetRefreshTokenCookie(response.RefreshToken, response.Expires);
            }

            return Ok(response);
        }

        [HttpPost("Refresh-Token")]
        public async Task<IActionResult> RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];

            if (string.IsNullOrEmpty(refreshToken))
                return BadRequest(new { message = "Token is required" });

            var ipAddress = GetIpAddress();
            var response = await _userService.RefreshToken(refreshToken, ipAddress);

            if (response.RefreshToken != null)
            {
                SetRefreshTokenCookie(response.RefreshToken, response.Expires);
            }

            return Ok(response);
        }

        [Authorize]
        [HttpPost("Revoke-Token")]
        public async Task<IActionResult> RevokeToken()
        {
            // Accept token from cookie
            var token = Request.Cookies["refreshToken"];

            if (string.IsNullOrEmpty(token))
                return BadRequest(new { message = "Token is required" });

            var ipAddress = GetIpAddress();

            await _userService.RevokeToken(token, ipAddress);
            return Ok(new { message = "Token revoked" });
        }

        // Helper methods
        private void SetRefreshTokenCookie(string token, DateTime expire)
        {
            _logger.LogInformation($"Setting refresh token cookie with expiration: {expire}");
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = expire,
                SameSite = SameSiteMode.Strict,
                Secure = true // Set to true in production with HTTPS
            };
            Response.Cookies.Append("refreshToken", token, cookieOptions);
        }

        private string GetIpAddress()
        {
            return HttpContext.Items["IpAddress"]?.ToString() ?? "unknown";
        }
    }
}

