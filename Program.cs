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
// ============================================================
builder.Services.AddAntiforgery(options =>
{
    options.FormFieldName = "__RequestVerificationToken";
    options.HeaderName = "X-CSRF-TOKEN";
    options.Cookie.Name = "CSRF-TOKEN";
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest; // Use .Always in production
    options.Cookie.SameSite = SameSiteMode.Strict;
});

// ============================================================
// DATA PROTECTION FOR ENCRYPTION (Section 2.1)
// ============================================================
builder.Services.AddDataProtection();

// ============================================================
// CREDIT CARD ENCRYPTION SERVICE (Section 2.1)
// ============================================================
builder.Services.AddScoped<ICreditCardEncryptionService, CreditCardEncryptionService>();

// ============================================================
// SECURE COOKIE CONFIGURATION (Section 2.3)
// ============================================================
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.Name = "SecureWebApp.Auth";
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest; // Use .Always in production
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
    options.SlidingExpiration = true;
    options.LoginPath = "/Account/Login";
    options.LogoutPath = "/Account/Logout";
    options.AccessDeniedPath = "/Account/AccessDenied";
});

// ============================================================
// SESSION CONFIGURATION
// ============================================================
builder.Services.AddSession(options =>
{
    options.Cookie.Name = "SecureWebApp.Session";
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest; // Use .Always in production
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