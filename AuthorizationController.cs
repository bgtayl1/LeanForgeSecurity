using System.Security.Claims;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace LeanForge.IdentityService.Controllers
{
    /// <summary>
    /// Explicitly handles OpenID Connect requests (Token Exchange).
    /// </summary>
    public class AuthorizationController : Controller
    {
        private readonly IOpenIddictApplicationManager _applicationManager;

        public AuthorizationController(IOpenIddictApplicationManager applicationManager)
        {
            _applicationManager = applicationManager;
        }

        [HttpPost("~/connect/token")]
        [IgnoreAntiforgeryToken]
        [Consumes("application/x-www-form-urlencoded")] // FIX: Ensure routing matches the content type
        [Produces("application/json")]
        public async Task<IActionResult> Exchange()
        {
            try
            {
                // Retrieve the OpenID Connect request from the ASP.NET Core context.
                var request = HttpContext.GetOpenIddictServerRequest();
                if (request == null)
                {
                    return BadRequest(new { error = "invalid_request", error_description = "The OpenID Connect request cannot be retrieved." });
                }

                // --- FLOW: Client Credentials (Microservice -> Microservice) ---
                if (request.IsClientCredentialsGrantType())
                {
                    // Retrieve the application (client) details from the database
                    var application = await _applicationManager.FindByClientIdAsync(request.ClientId);
                    if (application == null)
                    {
                        return BadRequest(new { error = "invalid_client", error_description = "The application identifier is invalid." });
                    }

                    // Create a new ClaimsIdentity containing the claims that will be used to create an id_token, a token or a code.
                    var identity = new ClaimsIdentity(
                        authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                        nameType: Claims.Name,
                        roleType: Claims.Role);

                    // Use the ClientId as the Subject (sub) and Name
                    identity.AddClaim(new Claim(Claims.Subject, request.ClientId!)
                        .SetDestinations(Destinations.AccessToken));

                    var displayName = await _applicationManager.GetDisplayNameAsync(application);
                    identity.AddClaim(new Claim(Claims.Name, displayName ?? request.ClientId!)
                        .SetDestinations(Destinations.AccessToken));

                    // --- ITAR COMPLIANCE LOGIC ---
                    // Inject the ITAR claim.
                    identity.AddClaim(new Claim("is_us_citizen", "true")
                        .SetDestinations(Destinations.AccessToken));

                    // Grant the requested scopes
                    identity.SetScopes(request.GetScopes());

                    // Create the Principal and sign it in
                    var principal = new ClaimsPrincipal(identity);

                    return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                }

                return BadRequest(new { error = "unsupported_grant_type", error_description = "The specified grant type is not supported." });
            }
            catch (Exception ex)
            {
                // Return a 500 with the specific exception message for debugging
                // Using an anonymous object ensures safe serialization
                return StatusCode(500, new
                {
                    error = "server_error",
                    error_description = $"An internal error occurred: {ex.Message}"
                });
            }
        }
    }
}