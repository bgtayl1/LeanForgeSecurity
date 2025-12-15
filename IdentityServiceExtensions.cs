using LeanForge.IdentityService.Data;
using LeanForge.IdentityService.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

// NOTE: We are removing the IdentityEF alias which caused the CS0234 error.
// We will rely on the standard AddIdentity call now that it's isolated.

namespace LeanForge.IdentityService.Extensions
{
    public static class IdentityServiceExtensions
    {
        public static IServiceCollection AddLeanForgeIdentity(this IServiceCollection services)
        {
            // --- 2. Configure ASP.NET Core Identity ---

            // FIX: Use the standard AddIdentity call now that the method is isolated 
            // in this separate extension file, minimizing ambiguity issues.
            var builder = services.AddIdentity<ApplicationUser, ApplicationRole>()
                .AddDefaultUI(); // AddDefaultUI returns IIdentityBuilder, which we save to 'builder'

            // Now that the Identity core is added, chain the EF Core stores and token providers onto the builder.
            builder
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

            // Separate configuration of IdentityOptions.
            services.Configure<IdentityOptions>(options =>
            {
                // Configure password complexity (Enforcing strong passwords)
                options.Password.RequireDigit = true;
                options.Password.RequireLowercase = true;
                options.Password.RequireUppercase = true;
                options.Password.RequiredLength = 12;

                // Enforce Multi-Factor Authentication (MFA) - Key Security Mandate
                options.SignIn.RequireConfirmedAccount = true;
            });

            return services;
        }
    }
}