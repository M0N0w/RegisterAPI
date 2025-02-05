using Microsoft.AspNetCore.Mvc;
using RegisterAPII.DTOs;
using RegisterAPII.Interfaces;

namespace RegisterAPII.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class PasswordController : ControllerBase
    {
        private readonly IAuthService _authService;

        public PasswordController(IAuthService authService)
        {
            _authService = authService;
        }

        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordDto dto)
        {
            var token = await _authService.ForgotPasswordAsync(dto);
            if (token == "User not found.")
                return NotFound(token);

            // Simulating token return for simplicity
            return Ok(new { ResetToken = token });
        }

        [HttpPost("reset-password/{token}")]
        public async Task<IActionResult> ResetPassword(string token, ResetPasswordDto dto)
        {
            var result = await _authService.ResetPasswordAsync(token, dto);
            if (result == "Invalid or expired token." || result == "Passwords do not match.")
                return BadRequest(result);

            return Ok(result);
        }
    }
}
