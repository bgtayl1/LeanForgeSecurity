using LeanForge.IdentityService.Data;      // To resolve ApplicationDbContext
using LeanForge.IdentityService.Models;    // To resolve ApplicationUser and ApplicationRole
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Diagnostics.EntityFrameworkCore; // Required for UseMigrationsEndPoint
using LeanForge.IdentityService;           // To resolve Config (if referenced) or SeedData
using Microsoft.Extensions.DependencyInjection; // Required for IServiceCollection
using Microsoft.AspNetCore.Builder;         // Required for IApplicationBuilder
// Removed ITARClaimHandler reference as we are switching to Controller-based handling
using Microsoft.AspNetCore.Identity.UI;     // Required for AddDefaultUI
using LeanForge.IdentityService.Extensions; // Required for AddLeanForgeIdentity extension method
using Microsoft.AspNetCore.Authentication;  // Required to fully resolve IdentityConstants
using OpenIddict.Server; // Required for OpenIddictServerEvents
using OpenIddict.Server.AspNetCore; // Required for OpenIddictServerAspNetCoreBuilderExtensions
using OpenIddict.Abstractions;

var builder = WebApplication.CreateBuilder(args);

// --- 1. Configure Database Connection (Onsite PostgreSQL Mandate) ---
var connectionString = builder.Configuration.GetConnectionString("OnsiteSqlConnection") ??
                       throw new InvalidOperationException("Connection string 'OnsiteSqlConnection' not found.");

builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseNpgsql(connectionString);
    // USING OPENDICT: Configure OpenIddict to use the same database context
    options.UseOpenIddict();
});

builder.Services.AddDatabaseDeveloperPageExceptionFilter();

// --- 2. Configure ASP.NET Core Identity ---
builder.Services.AddLeanForgeIdentity();

// Separate configuration of IdentityOptions.
builder.Services.Configure<IdentityOptions>(options =>
{
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequiredLength = 12;
    options.SignIn.RequireConfirmedAccount = true;
});


// --- 3. Configure OpenIddict (The Core Security Engine) ---
builder.Services.AddOpenIddict()
    // Configure OpenIddict to use the EF Core stores and context
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
               .UseDbContext<ApplicationDbContext>();
    })
    // Register the OpenIddict server components
    .AddServer(options =>
    {
        // Enable the Client Credentials flow (for Microservices) and Implicit/Authorization Code flows (for Clients)
        options.AllowClientCredentialsFlow();
        options.AllowAuthorizationCodeFlow().RequireProofKeyForCodeExchange();

        // Endpoint configuration
        options.SetAuthorizationEndpointUris("/connect/authorize")
               .SetTokenEndpointUris("/connect/token");

        // DEVELOPMENT ONLY: Disable HTTPS requirement for local testing
        options.DisableAccessTokenEncryption();
        options.AddDevelopmentEncryptionCertificate();
        options.AddDevelopmentSigningCertificate();

        // Register ASP.NET Core hosts
        options.UseAspNetCore()
               .EnableAuthorizationEndpointPassthrough()
               // FIX: Re-enable Passthrough. This tells OpenIddict "Don't handle the request yourself, 
               // pass it to the AuthorizationController". This is much easier to debug than Event Handlers.
               .EnableTokenEndpointPassthrough()
               .DisableTransportSecurityRequirement();
    })
    // Register the OpenIddict validation components
    .AddValidation(options =>
    {
        // Import configuration from the OpenIddict server instance.
        options.UseLocalServer();
        // Register ASP.NET Core hosts
        options.UseAspNetCore();
    });

// --- 4. Configure TLS/HTTPS (Data in Transit Encryption Mandate) ---
builder.Services.AddHsts(options =>
{
    options.Preload = true;
    options.IncludeSubDomains = true;
    options.MaxAge = TimeSpan.FromDays(365);
});

// --- 5. Other Standard Setup ---
builder.Services.AddControllersWithViews();
builder.Services.AddRazorPages();

// Need to call AddAuthentication *before* UseAuthorization
builder.Services.AddAuthentication();


var app = builder.Build();

// --- RUN DATABASE SEEDING ---
using (var scope = app.Services.CreateScope())
{
    var serviceProvider = scope.ServiceProvider;
    try
    {
        // Executes the seeding logic to create default roles, admin user, and OpenIddict Clients
        SeedData.EnsureSeedData(serviceProvider).Wait();
    }
    catch (Exception ex)
    {
        var logger = serviceProvider.GetRequiredService<ILogger<Program>>();
        logger.LogError(ex, "An error occurred while seeding the database.");
    }
}
// -----------------------------

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseMigrationsEndPoint();
}
else
{
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

// OPENDICT MIDDLEWARE: UseAuthentication and UseAuthorization must be here
app.UseAuthentication(); // OpenIddict requires this
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.MapRazorPages();

app.Run();