using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace WebApp_Core_Identity.Model
{
    public class AuthDbContext : IdentityDbContext
    {
        private readonly IConfiguration _configuration;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public DbSet<Auditlog> AuditLogs { get; set; }

        // Constructor for dependency injection
        public AuthDbContext(IConfiguration configuration, IHttpContextAccessor httpContextAccessor)
        {
            _configuration = configuration;
            _httpContextAccessor = httpContextAccessor;
        }

        // Override OnConfiguring to use connection string from configuration
        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            string connectionString = _configuration.GetConnectionString("AuthConnectionString");
            optionsBuilder.UseSqlServer(connectionString);
        }

        // Override OnModelCreating for entity configuration
        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            // Ensure Email is Unique
            builder.Entity<ApplicationUser>()
                .HasIndex(u => u.Email)
                .IsUnique();
        }

        // Overriding SaveChanges to encrypt data before saving
        public override int SaveChanges()
        {
            // Encrypt data before saving
            foreach (var entry in ChangeTracker.Entries<ApplicationUser>())
            {
                if (entry.State == EntityState.Added || entry.State == EntityState.Modified)
                {
                    if (entry.Entity.FirstName != null)
                    {
                        entry.Entity.FirstName = EncryptionHelper.EncryptData(entry.Entity.FirstName, EncryptionHelper.EncryptionKey, EncryptionHelper.IV);
                    }
                    if (entry.Entity.LastName != null)
                    {
                        entry.Entity.LastName = EncryptionHelper.EncryptData(entry.Entity.LastName, EncryptionHelper.EncryptionKey, EncryptionHelper.IV);
                    }
                    if (entry.Entity.Email != null)
                    {
                        entry.Entity.Email = EncryptionHelper.EncryptData(entry.Entity.Email, EncryptionHelper.EncryptionKey, EncryptionHelper.IV);
                    }
                }
            }

            return base.SaveChanges();
        }

        // Helper method to log audit data based on login activity
        public void LogAudit(ApplicationUser user, string activity)
        {
            var auditLog = new Auditlog
            {
                UserEmail = user.Email,
                Activity = activity,
                Details = $"User {user.UserName} performed {activity} action. IP: {GetIpAddress()}, Browser: {GetBrowserInfo()}",
                Timestamp = DateTime.UtcNow
            };

            AuditLogs.Add(auditLog);
            SaveChanges(); // Save the audit log separately
        }

        // Helper method to get the user's IP address
        private string GetIpAddress()
        {
            return _httpContextAccessor.HttpContext?.Connection?.RemoteIpAddress?.ToString();
        }

        // Helper method to get the browser information
        private string GetBrowserInfo()
        {
            return _httpContextAccessor.HttpContext?.Request?.Headers["User-Agent"].ToString();
        }
    }

    public class Auditlog
    {
        public int Id { get; set; }
        public string UserEmail { get; set; }
        public string Activity { get; set; } // "Login", "Failed Login", etc.
        public string Details { get; set; } // Additional information like IP Address, Browser, etc.
        public DateTime Timestamp { get; set; }
    }

    public class ApplicationUser : IdentityUser
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Gender { get; set; }
        public byte[] NRIC { get; set; }
        public DateOnly? DateOfBirth { get; set; }
        public byte[] Resume { get; set; }
        public string WhoAmI { get; set; }

        public string? SessionId { get; set; }

        public DateTime LastPasswordChangeDate { get; set; }

        // Properties for decrypted fields
        public string DecryptedFirstName => EncryptionHelper.DecryptData(this.FirstName, EncryptionHelper.EncryptionKey, EncryptionHelper.IV);
        public string DecryptedLastName => EncryptionHelper.DecryptData(this.LastName, EncryptionHelper.EncryptionKey, EncryptionHelper.IV);
        public string DecryptedEmail => EncryptionHelper.DecryptData(this.Email, EncryptionHelper.EncryptionKey, EncryptionHelper.IV);

        public string DecryptedNRIC => EncryptionHelper.DecryptNRIC(this.NRIC, EncryptionHelper.EncryptionKey, EncryptionHelper.IV);

        // Override UserName to fall back to Email if UserName is null
        public override string UserName
        {
            get => base.UserName ?? base.Email;
            set => base.UserName = value ?? base.Email;
        }
    }
}
