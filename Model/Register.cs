using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using WebApplication1.ViewModels;

namespace WebApplication1.Model
{
    public class Register
    {
        [Required]
        [StringLength(50)]
        public string FirstName { get; set; }

        [Required]
        [StringLength(50)]
        public string LastName { get; set; }

        [Required]
        public string Gender { get; set; } // Consider using an Enum

        public string NRIC { get; set; }

        [Required]
        [DataType(DataType.EmailAddress)]
        [Remote("CheckEmailExists", "user", ErrorMessage = "Email address has already been taken.Please use another one")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Password is required.")]
        [StringLength(100, MinimumLength = 12, ErrorMessage = "Password must be at least 12 characters long.")]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()]).{12,}$",
               ErrorMessage = "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character.")]
        public string Password { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [Compare(nameof(Password), ErrorMessage = "Password and confirmation password do not match")]
        public string ConfirmPassword { get; set; }

        [Required]
        [DataType(DataType.Date)]
        public DateOnly DateOfBirth { get; set; }

        [NotMapped] // This prevents ResumeFile from being mapped to the database
        [AllowedExtensions(new string[] { ".pdf", ".docx", ".jpg" })] // Custom validation attribute
        public IFormFile ResumeFile { get; set; }

        [Required]
        [StringLength(500)] // Adjust limit as needed
        public string WhoAmI { get; set; } // Allows special characters


    }

}
