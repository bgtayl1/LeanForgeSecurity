using Microsoft.AspNetCore.Identity; // Essential for IdentityRole

namespace LeanForge.IdentityService.Models
{
    // The ApplicationRole extends the default IdentityRole for RBAC.
    public class ApplicationRole : IdentityRole
    {
        /// <summary>
        /// Description of the role, useful for non-technical users managing permissions.
        /// </summary>
        public string? Description { get; set; }
    }
}