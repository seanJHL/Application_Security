using System;

namespace SecureWebApp.Models;

/// <summary>
/// Entity for storing encrypted credit card information (Section 2.1).
/// Card numbers and cardholder names are encrypted using AES-256.
/// </summary>
public class StoredCreditCard
{
    public int Id { get; set; }

    /// <summary>
    /// Foreign key to the user who owns this card.
    /// </summary>
    public string UserId { get; set; } = string.Empty;

    /// <summary>
    /// Navigation property to the user.
    /// </summary>
    public virtual ApplicationUser User { get; set; } = null!;

    /// <summary>
    /// AES-256 encrypted credit card number (Section 2.1).
    /// </summary>
    public string EncryptedCardNumber { get; set; } = string.Empty;

    /// <summary>
    /// Last 4 digits of the card (stored in plain text for display purposes).
    /// </summary>
    public string LastFourDigits { get; set; } = string.Empty;

    /// <summary>
    /// Card brand (Visa, Mastercard, etc.).
    /// </summary>
    public string CardBrand { get; set; } = string.Empty;

    /// <summary>
    /// AES-256 encrypted cardholder name (Section 2.1).
    /// </summary>
    public string EncryptedCardholderName { get; set; } = string.Empty;

    /// <summary>
    /// Expiry month (1-12).
    /// </summary>
    public int ExpiryMonth { get; set; }

    /// <summary>
    /// Expiry year (4-digit).
    /// </summary>
    public int ExpiryYear { get; set; }

    /// <summary>
    /// When the card was added.
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// When the card was last updated.
    /// </summary>
    public DateTime? UpdatedAt { get; set; }
}
