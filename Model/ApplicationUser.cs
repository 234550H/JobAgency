using Microsoft.AspNetCore.Identity;

namespace WebApplication1.Model
{
    public class ApplicationUser : IdentityUser
    {
        // Your custom fields
        public string FirstName { get; set; }
        public string LastName { get; set; }

        public string? SessionId { get; set; }
        public string Gender { get; set; }
        public byte[] NRIC { get; set; }
        public DateOnly DateOfBirth { get; set; }
        public byte[] Resume { get; set; }
        public string WhoAmI { get; set; }

        public DateTime LastPasswordChangeDate { get; set; }

        public string? PreviousPasswordHash1 { get; set; }
        public string? PreviousPasswordHash2 { get; set; }

        // Define your key and IV (these should be securely stored, e.g., in a config or secure storage)
        private static readonly byte[] EncryptionKey = EncryptionHelper.Generate256BitKey();  // Example key
        private static readonly byte[] IV = EncryptionHelper.Generate128BitKey();  // Example IV

        // Decryption methods
        // Decrypted properties
        public string DecryptedFirstName => EncryptionHelper.DecryptData(FirstName, EncryptionKey, IV);
        public string DecryptedLastName => EncryptionHelper.DecryptData(LastName, EncryptionKey, IV);
        public string DecryptedEmail => EncryptionHelper.DecryptData(Email, EncryptionKey, IV);

    }
   


}

