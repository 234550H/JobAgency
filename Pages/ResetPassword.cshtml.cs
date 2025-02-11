using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Threading.Tasks;

namespace WebApplication1.Pages.Account
{
    public class ResetPasswordModel : PageModel
    {
        private readonly UserManager<IdentityUser> userManager;

        public ResetPasswordModel(UserManager<IdentityUser> userManager)
        {
            this.userManager = userManager;
        }

        [BindProperty]
        public string Token { get; set; }

        [BindProperty]
        public string Email { get; set; }

        [BindProperty]
        public string Password { get; set; }

        [BindProperty]
        public string ConfirmPassword { get; set; }

        public async Task<IActionResult> OnGetAsync(string token, string email)
        {
            // Check if the token and email are provided in the query string
            if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(email))
            {
                // Handle invalid request (you can show an error message or redirect)
                return RedirectToPage("/Index");
            }

            // Set the Token and Email to bind them to the form
            Token = token;
            Email = email;

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (Password != ConfirmPassword)
            {
                ModelState.AddModelError(string.Empty, "Passwords do not match.");
                return Page();
            }

            var user = await userManager.FindByEmailAsync(Email);
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "No user found with that email.");
                return Page();
            }

            var result = await userManager.ResetPasswordAsync(user, Token, Password);
            if (result.Succeeded)
            {
                return RedirectToPage("/Login"); // Redirect to login after resetting password
            }
            else
            {
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
                return Page();
            }
        }
    }
}
