using System.Security.Claims;
using AspCoreApiWithJWT.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AspCoreApiWithJWT.Controllers
{
    [Authorize]
    [ApiController]
    [Route("api/[controller]")]
    public class UsersController : ControllerBase
    {
        private readonly IUserService _userService;

        public UsersController(IUserService userService)
        {
            _userService = userService;
        }

        [Authorize(Roles = "Admin")]
        [HttpGet]
        public async Task<IActionResult> GetAll()
        {
            var users = await _userService.GetAll();
            return Ok(users);
        }

  
        [HttpGet("profile")]
        public async Task<IActionResult> GetProfile()
        {
            // Get the current user ID from the claims
            var userIdValue = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (userIdValue == null || !int.TryParse(userIdValue, out var userId))
            {
                return Unauthorized();
            }

            var user = await _userService.GetById(userId);

            if (user == null)
                return NotFound();

            return Ok(user);
        }
    }
}

