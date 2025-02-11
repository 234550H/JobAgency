using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Newtonsoft.Json;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using WebApp_Core_Identity.Model;
using WebApplication1.Model;

namespace WebApplication1.Pages
{
    public class RegisterModel : PageModel
    {
        private readonly IHttpClientFactory _clientFactory;
        private UserManager<IdentityUser> userManager { get; }
        private SignInManager<IdentityUser> signInManager { get; }

        private readonly string _secretKey;

        // [Optional] The reCaptcha secret key is now fetched from appsettings.json
        // private const string SecretKey = "6LeTptAqAAAAAFoJiPsqH-ZUAcHz4BHfrnsxcOAM"; 

        [BindProperty]
        public Register RModel { get; set; }

        public RegisterModel(IHttpClientFactory clientFactory, UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, IConfiguration configuration)
        {
            _clientFactory = clientFactory;
            this.userManager = userManager;
            this.signInManager = signInManager;
            _secretKey = configuration["ReCaptcha:SecretKey"];
        }

        public void OnGet()
        {
        }

        // Save data into the database
        public async Task<IActionResult> OnPostAsync(string recaptchaResponse)
        {
            // Step 1: Verify reCaptcha
            if (string.IsNullOrEmpty(recaptchaResponse))
            {
                ModelState.AddModelError("", "reCaptcha response is missing. Please try again.");
                return Page();
            }

            var isCaptchaValid = await VerifyReCaptchaAsync(recaptchaResponse);
            if (!isCaptchaValid)
            {
                ModelState.AddModelError("", "reCaptcha verification failed. Please try again.");
                return Page();
            }

            if (ModelState.IsValid)
            {
                // Step 2: Validate the resume file (if provided)
                byte[] resumeBytes = null;
                if (RModel.ResumeFile != null)
                {
                    // Check file size and type (e.g., only allow PDFs or Word documents)
                    if (RModel.ResumeFile.Length > 5 * 1024 * 1024) // 5 MB max size
                    {
                        ModelState.AddModelError("RModel.ResumeFile", "File size exceeds the maximum allowed size of 5 MB.");
                        return Page();
                    }

                    var allowedExtensions = new[] { ".pdf", ".doc", ".docx" };
                    var fileExtension = Path.GetExtension(RModel.ResumeFile.FileName).ToLower();
                    if (!allowedExtensions.Contains(fileExtension))
                    {
                        ModelState.AddModelError("RModel.ResumeFile", "Invalid file type. Only PDF and Word documents are allowed.");
                        return Page();
                    }

                    // Convert ResumeFile to byte[] if valid
                    using (var memoryStream = new MemoryStream())
                    {
                        await RModel.ResumeFile.CopyToAsync(memoryStream);
                        resumeBytes = memoryStream.ToArray(); // Convert to byte[]
                    }
                }

                // Step 3: Convert NRIC string to byte array (UTF-8 encoding) - or use string if needed
                byte[] nricBytes = Encoding.UTF8.GetBytes(RModel.NRIC);

                // Step 4: Create the user with the NRIC as byte[] and email passed to both UserName and Email
                var user = new WebApp_Core_Identity.Model.ApplicationUser()
                {
                    UserName = RModel.Email,   // Use email as the username
                    Email = RModel.Email,      // Explicitly set email as the Email
                    FirstName = RModel.FirstName,
                    DateOfBirth = RModel.DateOfBirth,
                    LastName = RModel.LastName,
                    NRIC = nricBytes,          // Store NRIC as byte[] (or string if preferred)
                    Gender = RModel.Gender,
                    Resume = resumeBytes,      // Store resume as byte[] (if provided)
                    WhoAmI = RModel.WhoAmI
                };

                // Step 5: Create the user in the system
                var result = await userManager.CreateAsync(user,RModel.Password);

                if (result.Succeeded)
                {
                    // Sign in the user after successful registration
                    await signInManager.SignInAsync(user, false);
                    return RedirectToPage("Index"); // Redirect to a page after successful registration
                }

                // Handle errors and provide feedback for user
                foreach (var error in result.Errors)
                {
                    if (error.Code == "DuplicateEmail")
                    {
                        ModelState.AddModelError("RModel.Email", "Email address has already been taken.");
                    }
                    else
                    {
                        ModelState.AddModelError("", error.Description);
                    }
                }
            }

            return Page();
        }

        private async Task<bool> VerifyReCaptchaAsync(string recaptchaResponse)
        {
            var client = _clientFactory.CreateClient();

            var postData = new FormUrlEncodedContent(new[] {
                new KeyValuePair<string, string>("secret", _secretKey),  // Use _secretKey from config
                new KeyValuePair<string, string>("response", recaptchaResponse)
            });

            var response = await client.PostAsync("https://www.google.com/recaptcha/api/siteverify", postData);
            var responseContent = await response.Content.ReadAsStringAsync();

            // Log the response for debugging purposes
            Console.WriteLine($"ReCaptcha Response: {responseContent}");

            dynamic jsonResponse = JsonConvert.DeserializeObject(responseContent);
            return jsonResponse.success == true;
        }

    }
}