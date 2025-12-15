using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using LeanForge.IdentityService.Models;

namespace LeanForge.IdentityService.Data
{
    /// <summary>
    /// The application's database context, combining the schema for
    /// ASP.NET Core Identity (users/roles) and OpenIddict (clients/tokens).
    /// </summary>
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser, ApplicationRole, string>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            // --- OpenIddict Integration ---
            // This tells Entity Framework to include all necessary OpenIddict tables 
            // (e.g., OpenIddictApplications, OpenIddictTokens) in the database schema.
            builder.UseOpenIddict();
        }
    }
}