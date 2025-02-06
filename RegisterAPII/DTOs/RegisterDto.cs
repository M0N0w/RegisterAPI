using System.ComponentModel.DataAnnotations;

namespace RegisterAPII.DTOs
{
    public class RegisterDto
    {
        [Required]
        public string FullName { get; set; }

        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        [MinLength(5, ErrorMessage = "Password must be at least 5 characters long.")]
        [RegularExpression(@"^(?=.*[A-Z])(?=.*\d).+$", ErrorMessage = "Password must contain at least one uppercase letter and one number.")]
        public string Password { get; set; }
    }
}
