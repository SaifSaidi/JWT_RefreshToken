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

        [HttpGet]
        public async Task<IActionResult> GetAll()
        {
            var users = await _userService.GetAll();
            return Ok(users);
        }

        [HttpGet("{id}")]
        public async Task<IActionResult> GetById(int id)
        {
            var user = await _userService.GetById(id);
            if (user == null)
                return NotFound();

            return Ok(user);
        }

        [HttpGet("profile")]
        public async Task<IActionResult> GetProfile()
        {
            // Get the current user ID from the claims
            var userId = int.Parse(User.FindFirst("id")?.Value);
            var user = await _userService.GetById(userId);

            if (user == null)
                return NotFound();

            return Ok(user);
        }
    }

}

