using LeanForge.IdentityService.Models;
using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;
using System.Security.Claims;
using static OpenIddict.Server.OpenIddictServerEvents;


namespace LeanForge.IdentityService.Services
{
    /// <summary>
    /// Handles token requests. 
    /// 1. For Client Credentials (Microservices): Creates the identity/principal.
    /// 2. For User Flows (Auth Code): Injects ITAR claims into the existing principal.
    /// </summary>
    public class ITARClaimHandler : IOpenIddictServerHandler<HandleTokenRequestContext>
    {
        private readonly UserManager<ApplicationUser> _userManager;

        public ITARClaimHandler(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }

        public async ValueTask HandleAsync(HandleTokenRequestContext context)
        {
            // If the request is already handled, don't interfere.
            if (context.IsRequestHandled)
            {
                return;
            }

            // --- SCENARIO 1: Client Credentials Flow (Microservice -> IdentityServer) ---
            if (context.Request.IsClientCredentialsGrantType())
            {
                // Create a new ClaimsIdentity for the application (microservice)
                var identity = new ClaimsIdentity(
                    authenticationType: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    nameType: OpenIddictConstants.Claims.Name,
                    roleType: OpenIddictConstants.Claims.Role);

                // Set the Subject claim to the ClientId (e.g., "quoting-module")
                identity.AddClaim(new Claim(OpenIddictConstants.Claims.Subject, context.ClientId!)
                    .SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken));

                // Add the Name claim (display name)
                // In a real app, you might look up the display name from the OpenIddictApplicationManager
                identity.AddClaim(new Claim(OpenIddictConstants.Claims.Name, context.ClientId!)
                    .SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken));

                // Grant the requested scopes (after validating they are allowed - OpenIddict does validation earlier)
                identity.SetScopes(context.Request.GetScopes());

                // Create the Principal and set it on the context
                context.Principal = new ClaimsPrincipal(identity);

                // Mark the request as handled so OpenIddict knows to issue the token.
                context.HandleRequest();

                return;
            }

            // --- SCENARIO 2: User Flows (e.g., Authorization Code) ---
            // If a principal already exists (from the Authorization Endpoint), we enrich it with ITAR claims.
            var principal = context.Principal;
            if (principal != null)
            {
                // Get the user's unique identifier (sub claim)
                var subjectId = principal.GetClaim(OpenIddictConstants.Claims.Subject);

                // If there is no subject, or the subject is the client itself, skip user lookup
                if (subjectId == null || subjectId == context.ClientId)
                {
                    return;
                }

                var user = await _userManager.FindByIdAsync(subjectId);
                if (user != null)
                {
                    var identity = (ClaimsIdentity)principal.Identity!;

                    // --- ITAR Compliance Logic: Core Gatekeeper ---
                    if (user.IsUSCitizen)
                    {
                        // Add the claim required by downstream microservices to access ITAR data.
                        identity.AddClaim(new Claim("is_us_citizen", "true")
                            .SetDestinations(OpenIddictConstants.Destinations.AccessToken));
                    }

                    // Ensure roles are included in the access token
                    var roles = await _userManager.GetRolesAsync(user);
                    foreach (var role in roles)
                    {
                        if (!identity.HasClaim(c => c.Type == ClaimTypes.Role && c.Value == role))
                        {
                            identity.AddClaim(new Claim(ClaimTypes.Role, role)
                               .SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken));
                        }
                    }
                }
            }
        }
    }
}