using System.ComponentModel.DataAnnotations;

namespace RegisterAPII.DTOs
{
    public class ResetPasswordDto
    {
        [Required]
        public string NewPassword { get; set; }

        [Required]
        public string ConfirmPassword { get; set; }
    }
}
