using RegisterAPII.DTOs;

namespace RegisterAPII.Interfaces
{
    public interface IAuthService
    {
        Task<string?> RegisterAsync(RegisterDto dto);
        Task<string?> LoginAsync(LoginDto dto);
        Task<string?> ForgotPasswordAsync(ForgotPasswordDto dto);
        Task<string?> ResetPasswordAsync(string token, ResetPasswordDto dto);
    }
}
