using Microsoft.AspNetCore.DataProtection;
using System;
using System.Linq;
using System.Security.Cryptography;

namespace SecureWebApp.Services;

/// <summary>
/// Interface for credit card encryption service (Section 2.1)
/// </summary>
public interface ICreditCardEncryptionService
{
    string EncryptCardNumber(string cardNumber);
    string DecryptCardNumber(string encryptedData);
    string EncryptCardholderName(string name);
    string DecryptCardholderName(string encryptedData);
    string GetMaskedCardNumber(string cardNumber);
    string DetectCardBrand(string cardNumber);
    bool IsValidCardNumber(string cardNumber);
}

/// <summary>
/// Credit card encryption service using ASP.NET Core Data Protection API (Section 2.1)
/// Implements AES-256-GCM encryption for credit card data
/// </summary>
public class CreditCardEncryptionService : ICreditCardEncryptionService
{
    private readonly IDataProtector _cardProtector;
    private readonly IDataProtector _nameProtector;
    private readonly ILogger<CreditCardEncryptionService> _logger;

    public CreditCardEncryptionService(
        IDataProtectionProvider provider,
        ILogger<CreditCardEncryptionService> logger)
    {
        // Create purpose-specific protectors for different data types
        _cardProtector = provider.CreateProtector("CreditCard.CardNumber.v1");
        _nameProtector = provider.CreateProtector("CreditCard.CardholderName.v1");
        _logger = logger;
    }

    /// <summary>
    /// Encrypt a credit card number
    /// </summary>
    public string EncryptCardNumber(string cardNumber)
    {
        if (string.IsNullOrEmpty(cardNumber))
            throw new ArgumentNullException(nameof(cardNumber));

        // Remove any spaces or dashes from card number
        cardNumber = new string(cardNumber.Where(char.IsDigit).ToArray());

        // Validate card number format using Luhn algorithm
        if (!IsValidCardNumber(cardNumber))
            throw new ArgumentException("Invalid card number", nameof(cardNumber));

        try
        {
            return _cardProtector.Protect(cardNumber);
        }
        catch (CryptographicException ex)
        {
            _logger.LogError(ex, "Failed to encrypt card number");
            throw new InvalidOperationException("Encryption failed", ex);
        }
    }

    /// <summary>
    /// Decrypt a credit card number
    /// </summary>
    public string DecryptCardNumber(string encryptedData)
    {
        if (string.IsNullOrEmpty(encryptedData))
            throw new ArgumentNullException(nameof(encryptedData));

        try
        {
            return _cardProtector.Unprotect(encryptedData);
        }
        catch (CryptographicException ex)
        {
            _logger.LogError(ex, "Failed to decrypt card number");
            throw new InvalidOperationException("Decryption failed - data may be corrupted", ex);
        }
    }

    /// <summary>
    /// Encrypt cardholder name
    /// </summary>
    public string EncryptCardholderName(string name)
    {
        if (string.IsNullOrEmpty(name))
            throw new ArgumentNullException(nameof(name));

        try
        {
            return _nameProtector.Protect(name);
        }
        catch (CryptographicException ex)
        {
            _logger.LogError(ex, "Failed to encrypt cardholder name");
            throw new InvalidOperationException("Encryption failed", ex);
        }
    }

    /// <summary>
    /// Decrypt cardholder name
    /// </summary>
    public string DecryptCardholderName(string encryptedData)
    {
        if (string.IsNullOrEmpty(encryptedData))
            throw new ArgumentNullException(nameof(encryptedData));

        try
        {
            return _nameProtector.Unprotect(encryptedData);
        }
        catch (CryptographicException ex)
        {
            _logger.LogError(ex, "Failed to decrypt cardholder name");
            throw new InvalidOperationException("Decryption failed - data may be corrupted", ex);
        }
    }

    /// <summary>
    /// Get masked card number showing only last 4 digits
    /// </summary>
    public string GetMaskedCardNumber(string cardNumber)
    {
        cardNumber = new string(cardNumber.Where(char.IsDigit).ToArray());

        if (cardNumber.Length < 4)
            return "****";

        return "**** **** **** " + cardNumber.Substring(cardNumber.Length - 4);
    }

    /// <summary>
    /// Detect card brand based on card number prefix
    /// </summary>
    public string DetectCardBrand(string cardNumber)
    {
        cardNumber = new string(cardNumber.Where(char.IsDigit).ToArray());

        if (string.IsNullOrEmpty(cardNumber))
            return "Unknown";

        // Visa: starts with 4
        if (cardNumber.StartsWith("4"))
            return "Visa";

        // MasterCard: starts with 51-55 or 2221-2720
        if (cardNumber.Length >= 2)
        {
            int prefix2 = int.Parse(cardNumber.Substring(0, 2));
            if (prefix2 >= 51 && prefix2 <= 55)
                return "MasterCard";
        }

        if (cardNumber.Length >= 4)
        {
            int prefix4 = int.Parse(cardNumber.Substring(0, 4));
            if (prefix4 >= 2221 && prefix4 <= 2720)
                return "MasterCard";
        }

        // American Express: starts with 34 or 37
        if (cardNumber.StartsWith("34") || cardNumber.StartsWith("37"))
            return "American Express";

        // Discover: starts with 6011, 644-649, or 65
        if (cardNumber.StartsWith("6011") || cardNumber.StartsWith("65"))
            return "Discover";

        if (cardNumber.Length >= 3)
        {
            int prefix3 = int.Parse(cardNumber.Substring(0, 3));
            if (prefix3 >= 644 && prefix3 <= 649)
                return "Discover";
        }

        return "Unknown";
    }

    /// <summary>
    /// Validate card number using Luhn algorithm
    /// </summary>
    public bool IsValidCardNumber(string cardNumber)
    {
        cardNumber = new string(cardNumber.Where(char.IsDigit).ToArray());

        if (string.IsNullOrEmpty(cardNumber) || cardNumber.Length < 13 || cardNumber.Length > 19)
            return false;

        int sum = 0;
        bool alternate = false;

        for (int i = cardNumber.Length - 1; i >= 0; i--)
        {
            int digit = cardNumber[i] - '0';

            if (alternate)
            {
                digit *= 2;
                if (digit > 9)
                    digit -= 9;
            }

            sum += digit;
            alternate = !alternate;
        }

        return sum % 10 == 0;
    }
}