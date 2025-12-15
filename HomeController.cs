using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace LeanForge.IdentityService.Controllers
{
    /// <summary>
    /// The default controller for the Identity Service Module.
    /// Redirects the user immediately to the Login/Registration UI or a status page.
    /// </summary>
    [AllowAnonymous]
    public class HomeController : Controller
    {
        /// <summary>
        /// Default entry point for the application. Redirects authenticated users to the Endpoints page.
        /// </summary>
        public IActionResult Index()
        {
            // FIX: Check if the user is already authenticated.
            if (User.Identity != null && User.Identity.IsAuthenticated)
            {
                // If logged in, redirect to a safe, authenticated status page.
                // We'll use the Endpoints action to show the user they are authenticated.
                return RedirectToAction("Endpoints");
            }

            // If not logged in, redirect to the scaffolded Identity Login page.
            return LocalRedirect("/Identity/Account/Login");
        }

        /// <summary>
        /// Displays the Discovery Document link and information for API developers.
        /// This is useful for testing the token endpoints.
        /// </summary>
        public IActionResult Endpoints()
        {
            // This page serves as the authenticated landing page.
            // It uses a simple Content response as we have no Razor View defined for it.
            ViewBag.DiscoveryUrl = Url.Action("Discovery", "OpenIddict", null, Request.Scheme);

            return Content(
                $"Welcome, {User.Identity?.Name}! Your Identity Service Module is running and ready to issue tokens." +
                $"\n\nDiscovery Document URL: {Request.Scheme}://{Request.Host.Value}/.well-known/openid-configuration"
            );
        }
    }
}