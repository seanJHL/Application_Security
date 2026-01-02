using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace SecureWebApp.Models;

/// <summary>
/// View model for payment form with validation (Section 2.2)
/// Implements input validation to prevent SQL injection
/// </summary>
public class PaymentViewModel : IValidatableObject
{
    [Required(ErrorMessage = "Card number is required")]
    [CreditCard(ErrorMessage = "Invalid credit card number")]
    [StringLength(19, MinimumLength = 13, ErrorMessage = "Card number must be 13-19 digits")]
    [RegularExpression(@"^[0-9\s\-]+$", ErrorMessage = "Card number can only contain digits, spaces, and dashes")]
    [Display(Name = "Card Number")]
    public string CardNumber { get; set; } = string.Empty;

    [Required(ErrorMessage = "Cardholder name is required")]
    [StringLength(100, MinimumLength = 2, ErrorMessage = "Name must be 2-100 characters")]
    [RegularExpression(@"^[a-zA-Z\s\-\.]+$", ErrorMessage = "Name can only contain letters, spaces, hyphens, and periods")]
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

    [Required(ErrorMessage = "CVV is required")]
    [StringLength(4, MinimumLength = 3, ErrorMessage = "CVV must be 3-4 digits")]
    [RegularExpression(@"^[0-9]+$", ErrorMessage = "CVV can only contain digits")]
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