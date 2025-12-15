using LeanForge.IdentityService.Models;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;
using OpenIddict.Abstractions; // New: Required for OpenIddict client management

namespace LeanForge.IdentityService.Data
{
    public static class SeedData
    {
        public const string AdminRole = "SystemAdmin";
        public const string ItarAdminRole = "ITAR_Data_Admin";

        /// <summary>
        /// Ensures necessary roles, a default administrator user, and OpenIddict clients exist in the database.
        /// </summary>
        public static async Task EnsureSeedData(IServiceProvider serviceProvider)
        {
            var roleManager = serviceProvider.GetRequiredService<RoleManager<ApplicationRole>>();
            var userManager = serviceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            // New: Get the OpenIddict Application Manager for client registration
            var applicationManager = serviceProvider.GetRequiredService<IOpenIddictApplicationManager>();

            // --- 1. Seed Roles for RBAC ---

            // Create SystemAdmin Role
            if (await roleManager.FindByNameAsync(AdminRole) == null)
            {
                var role = new ApplicationRole
                {
                    Name = AdminRole,
                    Description = "Full access and configuration rights over the entire ERP system."
                };
                await roleManager.CreateAsync(role);
            }

            // Create ITAR Data Admin Role (Requires IsUSCitizen = true)
            if (await roleManager.FindByNameAsync(ItarAdminRole) == null)
            {
                var role = new ApplicationRole
                {
                    Name = ItarAdminRole,
                    Description = "Access to ITAR-controlled blueprints and technical data."
                };
                await roleManager.CreateAsync(role);
            }

            // --- 2. Seed Default Administrator User (ITAR-Compliant) ---

            const string adminEmail = "admin@leanforge.local";
            const string adminPassword = "SecurePassword123!"; // **CHANGE THIS IN PRODUCTION**

            if (await userManager.FindByNameAsync(adminEmail) == null)
            {
                var adminUser = new ApplicationUser
                {
                    UserName = adminEmail,
                    Email = adminEmail,
                    EmailConfirmed = true,
                    // !!! CRITICAL for ITAR Compliance Testing !!!
                    IsUSCitizen = true,
                    EmployeeId = "A0001"
                };

                var result = await userManager.CreateAsync(adminUser, adminPassword);
                if (result.Succeeded)
                {
                    // Assign Roles
                    await userManager.AddToRoleAsync(adminUser, AdminRole);
                    await userManager.AddToRoleAsync(adminUser, ItarAdminRole);
                }
            }

            // --- 3. Seed OpenIddict Microservice Clients (REPLACES Config.cs) ---

            // Client 1: Quoting Module (Full access to quoting data, general API access)
            const string quotingModuleClientId = "quoting-module";
            if (await applicationManager.FindByClientIdAsync(quotingModuleClientId) is null)
            {
                await applicationManager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientId = quotingModuleClientId,
                    ClientSecret = "secret-for-quoting-module-prod",
                    DisplayName = "Quoting Microservice Module",
                    // Allows the client credentials flow and defines the authorized scopes
                    Permissions =
                    {
                        OpenIddictConstants.Permissions.Endpoints.Token,
                        OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
                        OpenIddictConstants.Permissions.Prefixes.Scope + "quoting.full",
                        OpenIddictConstants.Permissions.Prefixes.Scope + "general.api"
                    }
                });
            }

            // Client 2: Inventory Module (Read access to inventory data, general API access)
            const string inventoryModuleClientId = "inventory-module";
            if (await applicationManager.FindByClientIdAsync(inventoryModuleClientId) is null)
            {
                await applicationManager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientId = inventoryModuleClientId,
                    ClientSecret = "secret-for-inventory-module-prod",
                    DisplayName = "Inventory Microservice Module",
                    Permissions =
                    {
                        OpenIddictConstants.Permissions.Endpoints.Token,
                        OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
                        OpenIddictConstants.Permissions.Prefixes.Scope + "inventory.read",
                        OpenIddictConstants.Permissions.Prefixes.Scope + "general.api"
                    }
                });
            }
        }
    }
}
