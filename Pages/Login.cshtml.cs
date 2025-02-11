using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Security.Claims;
using System.Text.RegularExpressions;
using WebApplication1.ViewModels;
using ApplicationUser = WebApp_Core_Identity.Model.ApplicationUser;
using Newtonsoft.Json;
using System.Text;
using WebApp_Core_Identity.Model; // Ensure you have the model namespace for Auditlog
using System.Threading.Tasks;

namespace WebApplication1.Pages
{
    public class LoginModel : PageModel
    {
        [BindProperty]
        public Login LModel { get; set; }

        private readonly SignInManager<IdentityUser> signInManager;
        private readonly UserManager<IdentityUser> userManager;
        private readonly IHttpClientFactory _clientFactory;
        private readonly string _secretKey;
        private readonly AuthDbContext _dbContext;

        public string LockoutMessage { get; set; }

        public LoginModel(SignInManager<IdentityUser> signInManager, UserManager<IdentityUser> userManager, IHttpClientFactory clientFactory, IConfiguration configuration, AuthDbContext dbContext)
        {
            this.signInManager = signInManager;
            this.userManager = userManager;
            _clientFactory = clientFactory;
            _secretKey = configuration["ReCaptcha:SecretKey"];
            _dbContext = dbContext; // Initialize your DbContext here
        }

        // OnGet: Handles GET request to render login page
        public IActionResult OnGet()
        {
            if (HttpContext.User.Identity.IsAuthenticated)
            {
                return RedirectToPage("/Index"); // Redirect logged-in users to Home
            }
            return Page();
        }

        // OnPostAsync: Handles POST request for login action
        public async Task<IActionResult> OnPostAsync(string recaptchaResponse)
        {
            // reCAPTCHA Verification
            if (string.IsNullOrEmpty(recaptchaResponse))
            {
                ModelState.AddModelError("", "reCAPTCHA response is missing. Please try again.");
                return Page();
            }

            var isCaptchaValid = await VerifyReCaptchaAsync(recaptchaResponse);
            if (!isCaptchaValid)
            {
                ModelState.AddModelError("", "reCAPTCHA verification failed. Please try again.");
                return Page();
            }

            // Email and Password validation
            if (ModelState.IsValid)
            {
                if (string.IsNullOrEmpty(LModel.Email))
                {
                    ModelState.AddModelError("LModel.Email", "Email cannot be null or empty.");
                    return Page();
                }

                if (!IsValidEmail(LModel.Email))
                {
                    ModelState.AddModelError("LModel.Email", "Invalid email address format.");
                    return Page();
                }

                // Additional checks for Password Strength (if needed)
                if (string.IsNullOrEmpty(LModel.Password))
                {
                    ModelState.AddModelError("LModel.Password", "Password cannot be empty.");
                    return Page();
                }
                if (!IsValidPassword(LModel.Password))
                {
                    ModelState.AddModelError("LModel.Password", "Password does not meet the required strength.");
                    return Page();
                }

                // Check if the user exists and account lockout status
                var user = await userManager.FindByEmailAsync(LModel.Email);
                if (user == null)
                {
                    LogAudit("Failed login attempt: User not found", LModel.Email); // Audit log
                    ModelState.AddModelError("", "Invalid username or password.");
                    return Page();
                }

                // Account lockout check
                if (await userManager.IsLockedOutAsync(user))
                {
                    LockoutMessage = "Your account is locked due to multiple failed login attempts. Please try again later.";
                    LogAudit("Failed login attempt: Account locked", LModel.Email); // Audit log
                    return Page();
                }

                // Check password validity
                var passwordValid = await userManager.CheckPasswordAsync(user, LModel.Password);
                if (!passwordValid)
                {
                    LogAudit("Failed login attempt: Incorrect password", LModel.Email); // Audit log
                    ModelState.AddModelError("", "Invalid username or password.");
                    return Page();
                }

                // Perform login attempt
                var identityResult = await signInManager.PasswordSignInAsync(user, LModel.Password, LModel.RememberMe, false);

                if (identityResult.Succeeded)
                {
                    // Reset failed login attempts
                    await userManager.ResetAccessFailedCountAsync(user);

                    // Generate a new session ID and store relevant user details in session
                    var sessionId = Guid.NewGuid().ToString();
                    HttpContext.Session.SetString("UserEmail", LModel.Email);
                    HttpContext.Session.SetString("SessionStartTime", DateTime.UtcNow.ToString());
                    HttpContext.Session.SetString("SessionId", sessionId);

                    // Store user-specific details in session
                    if (user is ApplicationUser applicationUser)
                    {
                        var firstName = applicationUser.FirstName ?? "N/A";
                        var lastName = applicationUser.LastName ?? "N/A";
                        var dob = applicationUser.DateOfBirth?.ToString("yyyy-MM-dd") ?? "N/A";
                        var gender = applicationUser.Gender ?? "N/A";
                        var whoami = applicationUser.WhoAmI ?? "N/A";

                        // NRIC & Resume
                        string nric = null;
                        string resume = "N/A";

                        if (applicationUser.NRIC != null)
                        {
                            nric = System.Text.Encoding.UTF8.GetString(applicationUser.NRIC); // Convert byte[] to string using UTF-8 encoding
                        }
                        else
                        {
                            nric = "N/A"; // Default value if NRIC is null
                        }

                        // Store details in session
                        HttpContext.Session.SetString("FirstName", firstName);
                        HttpContext.Session.SetString("LastName", lastName);
                        HttpContext.Session.SetString("DateOfBirth", dob);
                        HttpContext.Session.SetString("Gender", gender);
                        HttpContext.Session.SetString("NRIC", nric);
                        HttpContext.Session.SetString("whoami", whoami);

                        // Update session information in user model
                        applicationUser.SessionId = sessionId;
                        await userManager.UpdateAsync(applicationUser);
                    }

                    // Create authentication claims
                    var claims = new List<Claim> {
                new Claim(ClaimTypes.Name, LModel.Email),
                new Claim(ClaimTypes.Email, LModel.Email),
                new Claim("SessionStartTime", DateTime.UtcNow.ToString()),
                new Claim("SessionId", sessionId),
                new Claim("NRIC", HttpContext.Session.GetString("NRIC") ?? "") // Store NRIC claim
            };

                    var identity = new ClaimsIdentity(claims, "MyCookieAuth");
                    ClaimsPrincipal claimsPrincipal = new ClaimsPrincipal(identity);

                    // Sign in user
                    await HttpContext.SignInAsync("MyCookieAuth", claimsPrincipal);

                    LogAudit("User logged in successfully", LModel.Email); // Audit log

                    return RedirectToPage("/Index");
                }
                else
                {
                    // Handle failed login attempt and lockout after too many failed attempts
                    var failedAttempts = await userManager.GetAccessFailedCountAsync(user);
                    failedAttempts++;

                    if (failedAttempts >= 3)
                    {
                        await userManager.SetLockoutEnabledAsync(user, true);
                        await userManager.SetLockoutEndDateAsync(user, DateTime.UtcNow.AddMinutes(1));
                        LockoutMessage = "Your account has been locked due to too many failed login attempts. Please try again later.";
                        LogAudit("Account locked after multiple failed attempts", LModel.Email); // Audit log
                    }
                    else
                    {
                        user.AccessFailedCount = failedAttempts;
                        await userManager.UpdateAsync(user);
                    }

                    LogAudit("Failed login attempt: Incorrect password", LModel.Email); // Audit log
                    ModelState.AddModelError("", "Invalid username or password.");
                    return Page();
                }
            }

            return Page();
        }


        // Helper method to validate email format using regex
        private bool IsValidEmail(string email)
        {
            var emailRegex = new Regex(@"^[\w-]+(\.[\w-]+)*@([\w-]+\.)+[a-zA-Z]{2,7}$");
            return emailRegex.IsMatch(email);
        }

        // Helper method to validate password strength using regex
        private bool IsValidPassword(string password)
        {
            var passwordRegex = new Regex(@"^(?=.*[A-Z])(?=.*\d)[A-Za-z\d@$!%*?&]{8,}$");
            return passwordRegex.IsMatch(password);
        }

        // Google reCAPTCHA verification
        private async Task<bool> VerifyReCaptchaAsync(string recaptchaResponse)
        {
            var client = _clientFactory.CreateClient();
            var postData = new FormUrlEncodedContent(new[] {
                new KeyValuePair<string, string>("secret", _secretKey),
                new KeyValuePair<string, string>("response", recaptchaResponse)
            });

            var response = await client.PostAsync("https://www.google.com/recaptcha/api/siteverify", postData);
            var responseContent = await response.Content.ReadAsStringAsync();

            Console.WriteLine($"ReCaptcha Response: {responseContent}");

            dynamic jsonResponse = JsonConvert.DeserializeObject(responseContent);
            return jsonResponse.success == true;
        }

        // Helper method to log audit actions to the database
        private void LogAudit(string action, string email)
        {
            var auditLog = new Auditlog
            {
                UserEmail = email,
                Activity = action,
                Details = $"User {email} performed {action} action.",
                Timestamp = DateTime.UtcNow
            };

            // Add the new audit log record to the AuditLogs DbSet
            _dbContext.AuditLogs.Add(auditLog); // Use injected DbContext here

            // Save the changes to the database
            _dbContext.SaveChanges(); // Use injected DbContext here
        }
    }
}
