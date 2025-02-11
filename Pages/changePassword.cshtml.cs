using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Threading.Tasks;
using WebApplication1.ViewModels;

namespace WebApplication1.Pages
{
    public class ChangePasswordModel : PageModel
    {
        // Rename the property to avoid conflict with the class name
        [BindProperty]
        public ChangePasswordViewModel ChangePasswordViewModel { get; set; }

        private readonly UserManager<IdentityUser> userManager;
        private readonly SignInManager<IdentityUser> signInManager;

        public ChangePasswordModel(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
        }

        public IActionResult OnGet()
        {
            // Check if the user is authenticated, otherwise redirect to login
            if (!User.Identity.IsAuthenticated)
            {
                return RedirectToPage("/Login");
            }

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (ModelState.IsValid)
            {
                // Retrieve the logged-in user
                var user = await userManager.GetUserAsync(User);

                if (user == null)
                {
                    // If the user is not found
                    ModelState.AddModelError(string.Empty, "User not found.");
                    return Page();
                }

                // Change password logic
                if (ChangePasswordViewModel.NewPassword != ChangePasswordViewModel.ConfirmPassword)
                {
                    ModelState.AddModelError(string.Empty, "New password and confirmation do not match.");
                    return Page();
                }

                // Attempt to change the user's password
                var result = await userManager.ChangePasswordAsync(user, ChangePasswordViewModel.OldPassword, ChangePasswordViewModel.NewPassword);

                if (result.Succeeded)
                {

                    TempData["SuccessMessage"] = "Your password has been changed successfully.";

                    // Sign out after password change (optional, but often recommended)
                    await signInManager.SignOutAsync();

              
                    return RedirectToPage("/Index");
                }

                // If the password change failed, add the errors to ModelState
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
            }

            return Page();
        }
    }
}
