using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using SecureWebApp.Models;
using System;
using System.Security.Policy;
using System.Threading.Tasks;

namespace SecureWebApp.Controllers;

/// <summary>
/// Account controller handling login, registration, and logout
/// Implements security features from Sections 1.1, 1.2, 1.3
/// </summary>
public class AccountController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly ILogger<AccountController> _logger;

    public AccountController(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        ILogger<AccountController> logger)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _logger = logger;
    }

    // ============================================================
    // LOGIN - GET
    // ============================================================
    [HttpGet]
    [AllowAnonymous]
    public IActionResult Login(string? returnUrl = null)
    {
        ViewData["ReturnUrl"] = returnUrl;
        return View();
    }

    // ============================================================
    // LOGIN - POST (Section 1.1: Account Lockout, Section 1.3: CSRF)
    // ============================================================
    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken] // CSRF Protection (Section 1.3)
    public async Task<IActionResult> Login(LoginViewModel model, string? returnUrl = null)
    {
        ViewData["ReturnUrl"] = returnUrl;

        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var user = await _userManager.FindByEmailAsync(model.Email);

        // Check if account is locked out (Section 1.1)
        if (user != null)
        {
            if (await _userManager.IsLockedOutAsync(user))
            {
                var lockoutEnd = await _userManager.GetLockoutEndDateAsync(user);
                var remainingTime = lockoutEnd!.Value - DateTimeOffset.UtcNow;

                _logger.LogWarning(
                    "Locked out account login attempt for user {Email}. Lockout ends in {Minutes} minutes.",
                    model.Email,
                    remainingTime.TotalMinutes);

                ModelState.AddModelError(string.Empty,
                    $"Account is locked. Please try again in {Math.Ceiling(remainingTime.TotalMinutes)} minutes.");

                return View(model);
            }
        }

        // Attempt sign-in with lockout enabled (Section 1.1)
        var result = await _signInManager.PasswordSignInAsync(
            model.Email,
            model.Password,
            model.RememberMe,
            lockoutOnFailure: true // Enable lockout on failure
        );

        if (result.Succeeded)
        {
            _logger.LogInformation("User {Email} logged in successfully.", model.Email);

            // Update last login time
            if (user != null)
            {
                user.LastLoginAt = DateTime.UtcNow;
                await _userManager.UpdateAsync(user);
            }

            // Redirect to return URL or home
            if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            return RedirectToAction("Index", "Home");
        }

        if (result.IsLockedOut)
        {
            _logger.LogWarning("User {Email} account locked out after failed attempts.", model.Email);
            return RedirectToAction(nameof(Lockout));
        }

        // Generic error message to prevent username enumeration (Section 1.1)
        _logger.LogWarning("Invalid login attempt for {Email}.", model.Email);
        ModelState.AddModelError(string.Empty, "Invalid login attempt.");

        return View(model);
    }

    // ============================================================
    // LOCKOUT PAGE (Section 1.1)
    // ============================================================
    [HttpGet]
    [AllowAnonymous]
    public IActionResult Lockout()
    {
        return View();
    }

    // ============================================================
    // REGISTER - GET
    // ============================================================
    [HttpGet]
    [AllowAnonymous]
    public IActionResult Register()
    {
        return View();
    }

    // ============================================================
    // REGISTER - POST (Section 1.2: Password Hashing, Section 1.3: CSRF)
    // ============================================================
    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken] // CSRF Protection (Section 1.3)
    public async Task<IActionResult> Register(RegisterViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var user = new ApplicationUser
        {
            UserName = model.Email,
            Email = model.Email,
            FirstName = model.FirstName,
            LastName = model.LastName,
            CreatedAt = DateTime.UtcNow
        };

        // Password is hashed using Argon2id (Section 1.2)
        var result = await _userManager.CreateAsync(user, model.Password);

        if (result.Succeeded)
        {
            _logger.LogInformation("User {Email} created a new account.", model.Email);

            // Add user to default role
            await _userManager.AddToRoleAsync(user, "User");

            // Sign in the user
            await _signInManager.SignInAsync(user, isPersistent: false);

            return RedirectToAction("Index", "Home");
        }

        // Add errors to ModelState
        foreach (var error in result.Errors)
        {
            ModelState.AddModelError(string.Empty, error.Description);
        }

        return View(model);
    }

    // ============================================================
    // LOGOUT - POST (Section 1.3: CSRF)
    // ============================================================
    [HttpPost]
    [ValidateAntiForgeryToken] // CSRF Protection (Section 1.3)
    public async Task<IActionResult> Logout()
    {
        await _signInManager.SignOutAsync();
        _logger.LogInformation("User logged out.");
        return RedirectToAction("Index", "Home");
    }

    // ============================================================
    // ACCESS DENIED
    // ============================================================
    [HttpGet]
    public IActionResult AccessDenied()
    {
        return View();
    }
}