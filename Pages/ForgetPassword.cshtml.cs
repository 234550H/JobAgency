using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Threading.Tasks;

namespace WebApplication1.Pages
{
    public class ForgotPasswordModel : PageModel
    {
        private readonly UserManager<IdentityUser> userManager;
        private readonly IEmailSender emailSender; // You would use an email sender service to send the link

        public ForgotPasswordModel(UserManager<IdentityUser> userManager, IEmailSender emailSender)
        {
            this.userManager = userManager;
            this.emailSender = emailSender;
        }

        [BindProperty]
        public string Email { get; set; }

        public async Task<IActionResult> OnPostAsync()
        {
            if (string.IsNullOrEmpty(Email))
            {
                ModelState.AddModelError(string.Empty, "Email is required.");
                return Page();
            }

            var user = await userManager.FindByEmailAsync(Email);
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "No user found with that email.");
                return Page();
            }

            var token = await userManager.GeneratePasswordResetTokenAsync(user);
            var resetUrl = Url.Page("/ResetPassword", new { token, email = Email });

            // Generate the full URL including the scheme (http or https) and host (localhost or production)
            var fullResetUrl = $"{Request.Scheme}://{Request.Host}{resetUrl}";

            // Send the reset email with the link
            await emailSender.SendEmailAsync(Email, "Reset Password", $"Please reset your password by clicking <a href='{fullResetUrl}'>here</a>");

            return RedirectToPage("/ForgotPasswordConfirmation"); // Redirect to a confirmation page
        }
    }
}
