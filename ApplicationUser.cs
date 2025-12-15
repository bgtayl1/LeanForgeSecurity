using Microsoft.AspNetCore.Identity; // Essential for IdentityUser

namespace LeanForge.IdentityService.Models
{
    // The ApplicationUser extends the default IdentityUser to add custom properties.
    public class ApplicationUser : IdentityUser
    {
        // --- ITAR Compliance Field ---
        /// <summary>
        /// A crucial field required by the ITAR compliance mandate.
        /// Access to ITAR-controlled data must be restricted to US Citizens only.
        /// </summary>
        public bool IsUSCitizen { get; set; } = false;

        /// <summary>
        /// Links the security user to the core ERP Employee Module record.
        /// </summary>
        public string? EmployeeId { get; set; }
    }
}