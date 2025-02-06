using RegisterAPII.DTOs;
using RegisterAPII.Interfaces;
using RegisterAPII.Models;
using System;
using BCrypt.Net;
using System.Threading.Tasks;

namespace RegisterAPII.Repos
{
    public class AuthService : IAuthService
    {
        private readonly IUserRepository _userRepository;
        private readonly IJwtService _jwtService;
        private readonly EmailService _emailService;

        public AuthService(IUserRepository userRepository, IJwtService jwtService, EmailService emailService)
        {
            _userRepository = userRepository;
            _jwtService = jwtService;
            _emailService = emailService;
        }

        public async Task<string?> RegisterAsync(RegisterDto dto)
        {
            var existingUser = await _userRepository.GetUserByEmailAsync(dto.Email);
            if (existingUser != null)
                return "Email is already in use.";

            var user = new User
            {
                FullName = dto.FullName,
                Email = dto.Email,
                PasswordHash = BCrypt.Net.BCrypt.HashPassword(dto.Password)
            };

            await _userRepository.AddUserAsync(user);
            await _userRepository.SaveChangesAsync();

            var subject = "Hello in EventHub!";
            var body = $"Hello {dto.FullName},<br> Thanks for registering in Event Hub.";

            await _emailService.SendEmailAsync(dto.Email, subject, body);

            return "Registration successful.";
        }

        public async Task<string?> LoginAsync(LoginDto dto)
        {
            var user = await _userRepository.GetUserByEmailAsync(dto.Email);
            if (user == null)
                return "Email not registered.";

            if (!BCrypt.Net.BCrypt.Verify(dto.Password, user.PasswordHash))
                return "Incorrect password.";

            var token = _jwtService.GenerateToken(user);

            return token;
        }

        public async Task<string?> ForgotPasswordAsync(ForgotPasswordDto dto)
        {
            var user = await _userRepository.GetUserByEmailAsync(dto.Email);
            if (user == null)
                return "Email not registered.";

            var token = Guid.NewGuid().ToString();
            user.ResetToken = token;
            user.ResetTokenExpiry = DateTime.UtcNow.AddHours(1);
            await _userRepository.SaveChangesAsync();

            var subject = "Reset Your Password";
            var body = $"Use this token to reset your password: {token}";
            await _emailService.SendEmailAsync(dto.Email, subject, body);

            return "Token sent to your email.";
        }

        public async Task<string?> ResetPasswordAsync(string token, ResetPasswordDto dto)
        {
            var user = await _userRepository.GetUserByResetTokenAsync(token);
            if (user == null)
                return "Invalid or expired token.";

            if (dto.NewPassword != dto.ConfirmPassword)
                return "Passwords do not match.";

            user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(dto.NewPassword);
            user.ResetToken = null;
            user.ResetTokenExpiry = null;
            await _userRepository.SaveChangesAsync();

            return "Password changed successfully.";
        }
    }
}
