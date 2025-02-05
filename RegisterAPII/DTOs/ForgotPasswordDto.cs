using System.ComponentModel.DataAnnotations;

namespace RegisterAPII.DTOs
{
    public class ForgotPasswordDto
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
