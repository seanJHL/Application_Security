using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SecureWebApp.Data;
using SecureWebApp.Models;
using SecureWebApp.Services;
using System;
using System.Security.Claims;
using System.Threading.Tasks;

namespace SecureWebApp.Controllers;

/// <summary>
/// Payment controller handling credit card processing
/// Implements security features from Sections 2.1, 2.2, 2.3
/// </summary>
[Authorize] // Requires authentication
public class PaymentController : Controller
{
    private readonly ApplicationDbContext _context;
    private readonly ICreditCardEncryptionService _encryptionService;
    private readonly ILogger<PaymentController> _logger;

    public PaymentController(
        ApplicationDbContext context,
        ICreditCardEncryptionService encryptionService,
        ILogger<PaymentController> logger)
    {
        _context = context;
        _encryptionService = encryptionService;
        _logger = logger;
    }

    // ============================================================
    // PAYMENT PAGE - GET
    // ============================================================
    [HttpGet]
    public async Task<IActionResult> Index()
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

        // Get user's saved cards (Section 2.1 - encrypted storage)
        var savedCards = await _context.StoredCreditCards
            .Where(c => c.UserId == userId)
            .Select(c => new SavedCardViewModel
            {
                Id = c.Id,
                LastFourDigits = c.LastFourDigits,
                CardBrand = c.CardBrand,
                ExpiryMonth = c.ExpiryMonth,
                ExpiryYear = c.ExpiryYear
            })
            .ToListAsync();

        ViewBag.SavedCards = savedCards;

        return View(new PaymentViewModel { Amount = 100.00m });
    }

    // ============================================================
    // PROCESS PAYMENT - POST (Sections 2.1, 2.2, 2.3)
    // ============================================================
    [HttpPost]
    [ValidateAntiForgeryToken] // CSRF Protection (Section 1.3)
    public async Task<IActionResult> ProcessPayment(PaymentViewModel model)
    {
        // Server-side validation (Section 2.2 - SQL Injection Prevention)
        if (!ModelState.IsValid)
        {
            _logger.LogWarning(
                "Invalid payment data submitted by user {UserId}",
                User.FindFirstValue(ClaimTypes.NameIdentifier));

            return View("Index", model);
        }

        // Clean card number
        var cleanCardNumber = new string(model.CardNumber.Where(char.IsDigit).ToArray());

        // Additional server-side validation using Luhn algorithm (Section 2.2)
        if (!_encryptionService.IsValidCardNumber(cleanCardNumber))
        {
            _logger.LogWarning("Invalid card number checksum submitted");
            ModelState.AddModelError("CardNumber", "Invalid card number");
            return View("Index", model);
        }

        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

        try
        {
            // Entity Framework automatically uses parameterized queries (Section 2.2)
            // This prevents SQL injection
            var existingCard = await _context.StoredCreditCards
                .Where(c => c.UserId == userId)
                .Where(c => c.LastFourDigits == cleanCardNumber.Substring(cleanCardNumber.Length - 4))
                .FirstOrDefaultAsync();

            // Save card if requested (Section 2.1 - Encryption)
            if (model.SaveCard && existingCard == null)
            {
                var encryptedCard = new StoredCreditCard
                {
                    UserId = userId!,
                    EncryptedCardNumber = _encryptionService.EncryptCardNumber(cleanCardNumber),
                    LastFourDigits = cleanCardNumber.Substring(cleanCardNumber.Length - 4),
                    CardBrand = _encryptionService.DetectCardBrand(cleanCardNumber),
                    EncryptedCardholderName = _encryptionService.EncryptCardholderName(model.CardholderName),
                    ExpiryMonth = model.ExpiryMonth,
                    ExpiryYear = model.ExpiryYear,
                    CreatedAt = DateTime.UtcNow
                };

                _context.StoredCreditCards.Add(encryptedCard);
                await _context.SaveChangesAsync();

                _logger.LogInformation(
                    "Credit card saved for user {UserId} (Last 4: {Last4})",
                    userId,
                    encryptedCard.LastFourDigits);
            }

            // Process payment (in real app, call payment gateway here)
            // CVV is used for authorization but NEVER stored (PCI DSS)
            _logger.LogInformation(
                "Payment of {Amount:C} processed for user {UserId}",
                model.Amount,
                userId);

            TempData["SuccessMessage"] = $"Payment of {model.Amount:C} processed successfully!";
            TempData["MaskedCard"] = _encryptionService.GetMaskedCardNumber(cleanCardNumber);

            return RedirectToAction(nameof(Success));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Payment processing failed for user {UserId}", userId);
            ModelState.AddModelError(string.Empty, "Payment processing failed. Please try again.");
            return View("Index", model);
        }
    }

    // ============================================================
    // PAYMENT SUCCESS PAGE
    // ============================================================
    [HttpGet]
    public IActionResult Success()
    {
        return View();
    }

    // ============================================================
    // DELETE SAVED CARD
    // ============================================================
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> DeleteCard(int id)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

        // Parameterized query prevents SQL injection (Section 2.2)
        var card = await _context.StoredCreditCards
            .Where(c => c.Id == id && c.UserId == userId)
            .FirstOrDefaultAsync();

        if (card != null)
        {
            _context.StoredCreditCards.Remove(card);
            await _context.SaveChangesAsync();

            _logger.LogInformation(
                "Credit card {CardId} deleted for user {UserId}",
                id,
                userId);
        }

        return RedirectToAction(nameof(Index));
    }
}

/// <summary>
/// View model for displaying saved cards (no sensitive data)
/// </summary>
public class SavedCardViewModel
{
    public int Id { get; set; }
    public string LastFourDigits { get; set; } = string.Empty;
    public string CardBrand { get; set; } = string.Empty;
    public int ExpiryMonth { get; set; }
    public int ExpiryYear { get; set; }
}