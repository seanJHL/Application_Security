using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text.RegularExpressions;

namespace SecureWebApp.Models;

/// <summary>
/// View model for payment form with validation (Section 2.2)
/// Implements input validation to prevent SQL injection
/// </summary>
public class PaymentViewModel : IValidatableObject
{
    // ============================================================
    // STEP 4: WHITE LIST INPUT VALIDATION - Card Number
    // Only allows digits, spaces, and dashes - blocks SQL injection chars like ' " ; --
    // ============================================================
    [Required(ErrorMessage = "Card number is required")]
    [CreditCard(ErrorMessage = "Invalid credit card number")]
    [StringLength(19, MinimumLength = 13, ErrorMessage = "Card number must be 13-19 digits")]
    [RegularExpression(@"^[0-9\s\-]+$", ErrorMessage = "Card number can only contain digits, spaces, and dashes")] // Step 4: Whitelist - only 0-9, spaces, dashes allowed
    [Display(Name = "Card Number")]
    public string CardNumber { get; set; } = string.Empty;

    // ============================================================
    // STEP 4: WHITE LIST INPUT VALIDATION - Cardholder Name
    // Only allows letters, spaces, hyphens, periods - blocks SQL injection chars
    // ============================================================
    [Required(ErrorMessage = "Cardholder name is required")]
    [StringLength(100, MinimumLength = 2, ErrorMessage = "Name must be 2-100 characters")]
    [RegularExpression(@"^[a-zA-Z\s\-\.]+$", ErrorMessage = "Name can only contain letters, spaces, hyphens, and periods")] // Step 4: Whitelist - blocks ' " ; -- and other SQL injection characters
    [Display(Name = "Name on Card")]
    public string CardholderName { get; set; } = string.Empty;

    [Required(ErrorMessage = "Expiry month is required")]
    [Range(1, 12, ErrorMessage = "Month must be between 1 and 12")]
    [Display(Name = "Expiry Month")]
    public int ExpiryMonth { get; set; }

    [Required(ErrorMessage = "Expiry year is required")]
    [Range(2024, 2040, ErrorMessage = "Invalid expiry year")]
    [Display(Name = "Expiry Year")]
    public int ExpiryYear { get; set; }

    // ============================================================
    // STEP 4: WHITE LIST INPUT VALIDATION - CVV
    // Only allows 3-4 digits - no letters or special characters
    // ============================================================
    [Required(ErrorMessage = "CVV is required")]
    [StringLength(4, MinimumLength = 3, ErrorMessage = "CVV must be 3-4 digits")]
    [RegularExpression(@"^[0-9]+$", ErrorMessage = "CVV can only contain digits")] // Step 4: Whitelist - only digits 0-9 allowed
    [Display(Name = "CVV")]
    public string CVV { get; set; } = string.Empty;

    [Required(ErrorMessage = "Amount is required")]
    [Range(0.01, 1000000, ErrorMessage = "Amount must be between $0.01 and $1,000,000")]
    [DataType(DataType.Currency)]
    [Display(Name = "Payment Amount")]
    public decimal Amount { get; set; }

    [Display(Name = "Save card for future payments")]
    public bool SaveCard { get; set; }

    /// <summary>
    /// Custom validation for card expiry date
    /// </summary>
    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        var currentDate = DateTime.Now;
        var expiryDate = new DateTime(ExpiryYear, ExpiryMonth, 1).AddMonths(1).AddDays(-1);

        if (expiryDate < currentDate)
        {
            yield return new ValidationResult(
                "Card has expired",
                new[] { nameof(ExpiryMonth), nameof(ExpiryYear) }
            );
        }
    }
}

// ============================================================
// STEP 4: CUSTOM WHITE LIST VALIDATION ATTRIBUTES
// These provide additional defense-in-depth beyond RegularExpression
// XSS PROTECTION LAYER 3: Input validation with whitelist patterns
// ============================================================

/// <summary>
/// Step 4: WhiteListCardNumberAttribute - Only allows digits and spaces
/// Explicitly rejects SQL injection and XSS characters
/// </summary>
public class WhiteListCardNumberAttribute : ValidationAttribute
{
    // Step 4: Whitelist pattern - only digits, spaces, dashes allowed
    private static readonly Regex AllowedPattern = new Regex(@"^[0-9\s\-]+$", RegexOptions.Compiled);

    protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
    {
        if (value is string cardNumber)
        {
            // Step 4: Reject if contains any non-whitelisted characters
            if (!AllowedPattern.IsMatch(cardNumber))
            {
                return new ValidationResult("Card number contains invalid characters.");
            }

            var digitsOnly = new string(cardNumber.Where(char.IsDigit).ToArray());
            if (digitsOnly.Length < 13 || digitsOnly.Length > 19)
            {
                return new ValidationResult("Card number must be 13-19 digits.");
            }
        }
        return ValidationResult.Success;
    }
}

/// <summary>
/// Step 4: WhiteListNameAttribute - Only allows letters, spaces, hyphens, apostrophes
/// Explicitly blocks SQL injection AND XSS patterns for defense-in-depth
/// </summary>
public class WhiteListNameAttribute : ValidationAttribute
{
    // Step 4: Whitelist pattern - only letters, spaces, hyphens, apostrophes, periods
    private static readonly Regex AllowedPattern = new Regex(@"^[a-zA-Z\s\-'\.]+$", RegexOptions.Compiled);

    // Step 4: Explicitly block SQL injection patterns
    private static readonly string[] SqlInjectionPatterns = { "--", ";", "/*", "*/", "xp_", "UNION", "SELECT", "DROP", "INSERT", "DELETE", "UPDATE", "EXEC" };

    // XSS PROTECTION LAYER 3: Explicitly block XSS patterns
    // These patterns are blocked as defense-in-depth (Razor encoding handles the primary defense)
    private static readonly string[] XssPatterns = {
        "<script", "</script", "javascript:", "onerror=", "onload=", "onclick=",
        "onmouseover=", "onfocus=", "onblur=", "<iframe", "<object", "<embed",
        "<svg", "expression(", "vbscript:", "<img", "&#", "\\u00", "%3c", "%3e"
    };

    protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
    {
        if (value is string name)
        {
            // Step 4: Check for SQL injection patterns first
            foreach (var pattern in SqlInjectionPatterns)
            {
                if (name.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return new ValidationResult("Name contains invalid characters.");
                }
            }

            // XSS PROTECTION: Check for XSS patterns (defense-in-depth)
            foreach (var pattern in XssPatterns)
            {
                if (name.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return new ValidationResult("Name contains invalid characters.");
                }
            }

            // Step 4: Then check against whitelist
            if (!AllowedPattern.IsMatch(name))
            {
                return new ValidationResult("Name can only contain letters, spaces, and hyphens.");
            }
        }
        return ValidationResult.Success;
    }
}

/// <summary>
/// Step 4: WhiteListCVVAttribute - Only allows 3-4 digits
/// </summary>
public class WhiteListCVVAttribute : ValidationAttribute
{
    // Step 4: Whitelist pattern - only 3-4 digits allowed
    private static readonly Regex AllowedPattern = new Regex(@"^[0-9]{3,4}$", RegexOptions.Compiled);

    protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
    {
        if (value is string cvv && !AllowedPattern.IsMatch(cvv))
        {
            return new ValidationResult("CVV must be 3-4 digits only.");
        }
        return ValidationResult.Success;
    }
}

/// <summary>
/// XSS PROTECTION LAYER 3: General-purpose XSS validation attribute
/// Use this attribute on any user input field that may contain free-form text
/// This provides defense-in-depth alongside Razor's automatic output encoding
/// </summary>
public class AntiXssAttribute : ValidationAttribute
{
    // XSS attack patterns to block - comprehensive list for defense-in-depth
    private static readonly string[] XssPatterns = {
        // Script injection patterns
        "<script", "</script>", "javascript:", "vbscript:", "data:text/html",

        // Event handler injection (common XSS vectors)
        "onerror=", "onload=", "onclick=", "onmouseover=", "onmouseout=",
        "onfocus=", "onblur=", "onsubmit=", "onreset=", "onselect=",
        "onchange=", "oninput=", "onkeydown=", "onkeyup=", "onkeypress=",

        // HTML injection that can contain scripts
        "<iframe", "<frame", "<object", "<embed", "<applet", "<meta",
        "<link", "<style", "<base", "<form", "<input", "<button",

        // SVG-based XSS
        "<svg", "<animate", "<set",

        // Expression-based (legacy IE)
        "expression(", "behavior:",

        // Encoded payloads (URL/HTML encoding bypass attempts)
        "&#", "\\u00", "%3c", "%3e", "%22", "%27", "%3d",

        // Protocol handlers
        "file:", "ftp:",

        // Template injection
        "{{", "}}", "${", "<%", "%>"
    };

    // Alternative regex pattern for detecting encoded XSS attempts
    private static readonly Regex EncodedXssPattern = new Regex(
        @"(&#[xX]?[0-9a-fA-F]+;?)|(%[0-9a-fA-F]{2})|(\\.u[0-9a-fA-F]{4})",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
    {
        if (value is string input && !string.IsNullOrEmpty(input))
        {
            // Check for known XSS patterns (case-insensitive)
            foreach (var pattern in XssPatterns)
            {
                if (input.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return new ValidationResult(
                        $"The {validationContext.DisplayName} field contains potentially unsafe content.");
                }
            }

            // Check for encoded XSS attempts
            if (EncodedXssPattern.IsMatch(input))
            {
                return new ValidationResult(
                    $"The {validationContext.DisplayName} field contains encoded characters that are not allowed.");
            }
        }
        return ValidationResult.Success;
    }
}
