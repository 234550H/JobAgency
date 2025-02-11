using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using WebApplication1.Model;
using System.Threading.Tasks;
using WebApp_Core_Identity.Model; // This is for the audit log used in WebApp_Core_Identity

namespace WebApplication1.Pages
{
    public class LogoutModel : PageModel
    {
        private readonly SignInManager<IdentityUser> signInManager;
        private readonly UserManager<IdentityUser> userManager;
        private readonly AuthDbContext _context; // Assuming ApplicationDbContext contains the AuditLogs DbSet

        // Constructor
        public LogoutModel(SignInManager<IdentityUser> signInManager, UserManager<IdentityUser> userManager, AuthDbContext context)
        {
            this.signInManager = signInManager;
            this.userManager = userManager;
            _context = context;
        }

        // On Get for Logout
        public async Task<IActionResult> OnGetAsync()
        {
            return await PerformLogout();
        }

        public async Task<IActionResult> OnPostLogoutAsync()
        {
            return await PerformLogout();
        }

        public IActionResult OnPostDontLogoutAsync()
        {
            return RedirectToPage("Index");
        }

        private async Task<IActionResult> PerformLogout()
        {
            // Get the currently logged-in user
            var user = await userManager.GetUserAsync(User);

            // Securely clear all session data
            HttpContext.Session.Clear();

            // Sign out from Identity
            await signInManager.SignOutAsync();

            // Sign out from Cookie authentication scheme
            await HttpContext.SignOutAsync(IdentityConstants.ApplicationScheme);

            // Invalidate authentication cookies
            HttpContext.Response.Cookies.Delete(".AspNetCore.Identity.Application");

            // Log the logout action to audit logs
            if (user != null)
            {
                LogAudit("User logged out successfully", user.Email); // Audit log
            }

            // Redirect to Login page after successful logout
            return RedirectToPage("/Login");
        }

        // Helper method to log audit actions to the database
        private void LogAudit(string action, string email)
        {
            var auditLog = new WebApp_Core_Identity.Model.Auditlog
            {
                UserEmail = email,
                Activity = action,
                Details = $"User {email} performed {action} action.",
                Timestamp = DateTime.UtcNow
            };

            // Add the new audit log record to the AuditLogs DbSet
            _context.AuditLogs.Add(auditLog);

            // Save the changes to the database
            _context.SaveChanges();
        }
    }
}
