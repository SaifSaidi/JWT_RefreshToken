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

        public AuthController(IUserService userService)
        {
            _userService = userService;
        }

        [HttpPost("Login")]
        public async Task<IActionResult> Login(AuthRequest model)
        {
            var ipAddress = GetIpAddress();
            var response = await _userService.Authenticate(model, ipAddress);

            if (response == null)
                return BadRequest(new { message = "Username or password is incorrect" });
             
            SetRefreshTokenCookie(response.RefreshToken, response.Expires);

            return Ok(response);
        }

        [HttpPost("Register")]
        public async Task<IActionResult> Register(RegisterRequest model)
        {
            try
            {
                var ipAddress = GetIpAddress();
                
                var response = await _userService.Register(model, ipAddress);

                SetRefreshTokenCookie(response.RefreshToken, response.Expires);

                return Ok(response);
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        [HttpPost("Refresh-Token")]
        public async Task<IActionResult> RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];

            if (string.IsNullOrEmpty(refreshToken))
                return BadRequest(new { message = "Token is required" });

            var ipAddress = GetIpAddress();

            try
            {
                var response = await _userService.RefreshToken(refreshToken, ipAddress);
 
                SetRefreshTokenCookie(response.RefreshToken, response.Expires);
 
                return Ok(response);
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        [Authorize]
        [HttpPost("Revoke-Token")]
        public async Task<IActionResult> RevokeToken([FromBody] string? refreshToken)
        {
            // Accept token from request body or cookie
             
            var token = refreshToken ?? Uri.UnescapeDataString(Request.Cookies["refreshToken"]);
             

            if (string.IsNullOrEmpty(token))
                return BadRequest(new { message = "Token is required" });

            var ipAddress = GetIpAddress();

            try
            {
                await _userService.RevokeToken(token, ipAddress);
                return Ok(new { message = "Token revoked" });
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        // Helper methods
        private void SetRefreshTokenCookie(string token, DateTime expire)
        {
            Console.WriteLine($"Setting refresh token cookie: {token} with expiration: {expire}");
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
            // Get client IP address from the request
            if (Request.Headers.ContainsKey("X-Forwarded-For"))
                return Request.Headers["X-Forwarded-For"];
            else
                return HttpContext.Connection.RemoteIpAddress?.MapToIPv4().ToString() ?? "unknown";
        }
    }

}

