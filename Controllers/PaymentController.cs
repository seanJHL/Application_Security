using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SecureWebApp.Data;
using SecureWebApp.Models;
using SecureWebApp.Services;
using System;
using System.Data;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;

namespace SecureWebApp.Controllers;

/// <summary>
/// Payment controller handling credit card processing
/// Implements security features from Sections 2.1, 2.2, 2.3
///
/// Defense-in-Depth Layers:
/// - Step 3: Parameterized queries via Entity Framework and ADO.NET stored procedures
/// - Step 4: White list input validation (see PaymentViewModel.cs)
/// - Step 5: Low privileged database account (configured at database level)
/// </summary>
[Authorize] // Requires authentication
public class PaymentController : Controller
{
    private readonly ApplicationDbContext _context;
    private readonly ICreditCardEncryptionService _encryptionService;
    private readonly ILogger<PaymentController> _logger;
    private readonly IConfiguration _configuration;

    public PaymentController(
        ApplicationDbContext context,
        ICreditCardEncryptionService encryptionService,
        ILogger<PaymentController> logger,
        IConfiguration configuration)
    {
        _context = context;
        _encryptionService = encryptionService;
        _logger = logger;
        _configuration = configuration;
    }

    // ============================================================
    // PAYMENT PAGE - GET
    // ============================================================
    [HttpGet]
    public async Task<IActionResult> Index()
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

        // ============================================================
        // STEP 3: PARAMETERIZED QUERY via Entity Framework
        // Entity Framework automatically parameterizes this LINQ query
        // The userId is passed as a parameter, not concatenated into SQL
        // Generated SQL: SELECT ... FROM StoredCreditCards WHERE UserId = @p0
        // ============================================================
        var savedCards = await _context.StoredCreditCards
            .Where(c => c.UserId == userId)  // Step 3: userId is parameterized, prevents SQL injection
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
    // STEP 3: PARAMETERIZED STORED PROCEDURE EXAMPLE (ADO.NET)
    // This method demonstrates calling stored procedures with parameters
    // Provides additional abstraction layer beyond Entity Framework
    // ============================================================
    private async Task<List<SavedCardViewModel>> GetUserCardsViaStoredProcedure(string userId)
    {
        var cards = new List<SavedCardViewModel>();
        var connectionString = _configuration.GetConnectionString("DefaultConnection");

        // Step 3: Using ADO.NET with parameterized stored procedure
        using var connection = new SqliteConnection(connectionString);
        using var command = new SqliteCommand("sp_GetUserCreditCards", connection);

        // Step 3: Set command type to stored procedure
        command.CommandType = CommandType.Text; // SQLite uses Text, SQL Server uses StoredProcedure

        // Step 3: Add parameter with explicit type - prevents SQL injection
        // The @UserId parameter is safely bound, not string concatenated
        command.Parameters.Add("@UserId", SqliteType.Text).Value = userId;

        await connection.OpenAsync();

        // Step 3: Execute parameterized query safely
        using var reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            cards.Add(new SavedCardViewModel
            {
                Id = reader.GetInt32(0),
                CardBrand = reader.GetString(1),
                LastFourDigits = reader.GetString(2),
                ExpiryMonth = reader.GetInt32(3),
                ExpiryYear = reader.GetInt32(4)
            });
        }

        return cards;
    }

    // ============================================================
    // STEP 3: PARAMETERIZED INSERT via Stored Procedure (ADO.NET)
    // Demonstrates safe card insertion using parameters
    // ============================================================
    private async Task<int> SaveCardViaStoredProcedure(
        string userId,
        byte[] encryptedCardNumber,
        string cardBrand,
        string lastFourDigits,
        string cardholderName,
        int expiryMonth,
        int expiryYear)
    {
        var connectionString = _configuration.GetConnectionString("DefaultConnection");

        using var connection = new SqliteConnection(connectionString);
        using var command = new SqliteCommand();

        command.Connection = connection;
        // Step 3: Parameterized INSERT statement
        // All values are bound as parameters, not concatenated
        command.CommandText = @"
            INSERT INTO StoredCreditCards
                (UserId, EncryptedCardNumber, CardBrand, LastFourDigits,
                 EncryptedCardholderName, ExpiryMonth, ExpiryYear, CreatedAt)
            VALUES
                (@UserId, @EncryptedCardNumber, @CardBrand, @LastFourDigits,
                 @CardholderName, @ExpiryMonth, @ExpiryYear, @CreatedAt);
            SELECT last_insert_rowid();";

        // Step 3: All parameters are explicitly typed and bound safely
        command.Parameters.Add("@UserId", SqliteType.Text).Value = userId;
        command.Parameters.Add("@EncryptedCardNumber", SqliteType.Blob).Value = encryptedCardNumber;
        command.Parameters.Add("@CardBrand", SqliteType.Text).Value = cardBrand;
        command.Parameters.Add("@LastFourDigits", SqliteType.Text).Value = lastFourDigits;
        command.Parameters.Add("@CardholderName", SqliteType.Text).Value = cardholderName;
        command.Parameters.Add("@ExpiryMonth", SqliteType.Integer).Value = expiryMonth;
        command.Parameters.Add("@ExpiryYear", SqliteType.Integer).Value = expiryYear;
        command.Parameters.Add("@CreatedAt", SqliteType.Text).Value = DateTime.UtcNow.ToString("o");

        await connection.OpenAsync();

        // Step 3: Execute and return new ID
        var result = await command.ExecuteScalarAsync();
        return Convert.ToInt32(result);
    }

    // ============================================================
    // PROCESS PAYMENT - POST (Sections 2.1, 2.2, 2.3)
    // ============================================================
    [HttpPost]
    [ValidateAntiForgeryToken] // CSRF Protection (Section 1.3)
    public async Task<IActionResult> ProcessPayment(PaymentViewModel model)
    {
        // ============================================================
        // STEP 4: WHITE LIST INPUT VALIDATION
        // Model validation uses RegularExpression attributes that whitelist
        // allowed characters - see PaymentViewModel.cs for Step 4 implementation
        // This rejects SQL injection attempts like ' OR 1=1-- before processing
        // ============================================================
        if (!ModelState.IsValid)
        {
            _logger.LogWarning(
                "Invalid payment data submitted by user {UserId} - Step 4 validation rejected input",
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
            // ============================================================
            // STEP 3: PARAMETERIZED QUERY via Entity Framework
            // This LINQ query is automatically parameterized by EF Core
            // Both userId and lastFour are passed as @p0, @p1 parameters
            // SQL injection is impossible because values are never concatenated
            // ============================================================
            var existingCard = await _context.StoredCreditCards
                .Where(c => c.UserId == userId)  // Step 3: @p0 parameter
                .Where(c => c.LastFourDigits == cleanCardNumber.Substring(cleanCardNumber.Length - 4))  // Step 3: @p1 parameter
                .FirstOrDefaultAsync();

            // Save card if requested (Section 2.1 - Encryption)
            if (model.SaveCard && existingCard == null)
            {
                // ============================================================
                // STEP 3: PARAMETERIZED INSERT via Entity Framework
                // EF Core generates parameterized INSERT statement
                // All property values are bound as parameters
                // ============================================================
                var encryptedCard = new StoredCreditCard
                {
                    UserId = userId!,  // Step 3: Bound as @p0
                    EncryptedCardNumber = _encryptionService.EncryptCardNumber(cleanCardNumber),  // Step 3: Bound as @p1
                    LastFourDigits = cleanCardNumber.Substring(cleanCardNumber.Length - 4),  // Step 3: Bound as @p2
                    CardBrand = _encryptionService.DetectCardBrand(cleanCardNumber),  // Step 3: Bound as @p3
                    EncryptedCardholderName = _encryptionService.EncryptCardholderName(model.CardholderName),  // Step 3: Bound as @p4
                    ExpiryMonth = model.ExpiryMonth,  // Step 3: Bound as @p5
                    ExpiryYear = model.ExpiryYear,  // Step 3: Bound as @p6
                    CreatedAt = DateTime.UtcNow  // Step 3: Bound as @p7
                };

                // Step 3: EF Core Add() followed by SaveChangesAsync() generates parameterized INSERT
                _context.StoredCreditCards.Add(encryptedCard);
                await _context.SaveChangesAsync();

                _logger.LogInformation(
                    "Credit card saved for user {UserId} (Last 4: {Last4}) - Step 3 parameterized insert",
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

        // ============================================================
        // STEP 3: PARAMETERIZED QUERY via Entity Framework
        // Both 'id' and 'userId' are passed as parameters
        // Generated SQL: DELETE FROM StoredCreditCards WHERE Id = @p0 AND UserId = @p1
        // This prevents SQL injection even if 'id' were somehow manipulated
        // ============================================================
        var card = await _context.StoredCreditCards
            .Where(c => c.Id == id && c.UserId == userId)  // Step 3: Both values parameterized
            .FirstOrDefaultAsync();

        if (card != null)
        {
            // Step 3: EF Core Remove() generates parameterized DELETE
            _context.StoredCreditCards.Remove(card);
            await _context.SaveChangesAsync();

            _logger.LogInformation(
                "Credit card {CardId} deleted for user {UserId} - Step 3 parameterized delete",
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
