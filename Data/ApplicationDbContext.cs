using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using SecureWebApp.Models;

namespace SecureWebApp.Data;

/// <summary>
/// Application database context for Entity Framework Core
///
/// ============================================================
/// STEP 5: LOW PRIVILEGED DATABASE ACCOUNT
/// ============================================================
///
/// For production SQL Server deployments, configure a restricted database user:
///
/// -- Create restricted login and user
/// CREATE LOGIN SecureWebApp_User WITH PASSWORD = 'ComplexP@ssw0rd!2024';
/// USE SecureWebAppDb;
/// CREATE USER SecureWebApp_User FOR LOGIN SecureWebApp_User;
///
/// -- Grant only necessary permissions (principle of least privilege)
/// GRANT SELECT ON dbo.AspNetUsers TO SecureWebApp_User;
/// GRANT SELECT, INSERT, UPDATE, DELETE ON dbo.StoredCreditCards TO SecureWebApp_User;
/// GRANT SELECT, INSERT ON dbo.AuditLogs TO SecureWebApp_User;
///
/// -- Execute permission on stored procedures only
/// GRANT EXECUTE ON dbo.sp_GetUserCreditCards TO SecureWebApp_User;
/// GRANT EXECUTE ON dbo.sp_SaveCreditCard TO SecureWebApp_User;
///
/// -- Explicitly deny dangerous operations
/// DENY ALTER ON SCHEMA::dbo TO SecureWebApp_User;
/// DENY CREATE TABLE TO SecureWebApp_User;
/// DENY DROP TABLE TO SecureWebApp_User;
/// DENY EXECUTE ON xp_cmdshell TO SecureWebApp_User;
/// DENY VIEW ANY DATABASE TO SecureWebApp_User;
///
/// -- Prevent access to system tables (blocks information disclosure)
/// DENY SELECT ON sys.tables TO SecureWebApp_User;
/// DENY SELECT ON sys.columns TO SecureWebApp_User;
/// DENY SELECT ON INFORMATION_SCHEMA.TABLES TO SecureWebApp_User;
///
/// Connection string should use this restricted account:
/// "Server=...;Database=SecureWebAppDb;User Id=SecureWebApp_User;Password=...;TrustServerCertificate=True"
///
/// This limits damage even if SQL injection somehow succeeds (defense-in-depth).
/// </summary>
public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    // ============================================================
    // Credit card storage table (Section 2.1)
    // Step 5: Database user should have SELECT, INSERT, UPDATE, DELETE only
    // ============================================================
    public DbSet<StoredCreditCard> StoredCreditCards { get; set; }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        // Configure StoredCreditCard entity
        builder.Entity<StoredCreditCard>(entity =>
        {
            entity.HasKey(e => e.Id);

            // Step 5: Column constraints defined here are enforced by EF
            // Database-level constraints provide additional protection
            entity.Property(e => e.EncryptedCardNumber)
                .IsRequired()
                .HasMaxLength(500);

            entity.Property(e => e.LastFourDigits)
                .IsRequired()
                .HasMaxLength(4);

            entity.Property(e => e.CardBrand)
                .IsRequired()
                .HasMaxLength(50);

            entity.Property(e => e.EncryptedCardholderName)
                .IsRequired()
                .HasMaxLength(500);

            // Relationship with ApplicationUser
            // Step 5: Foreign key ensures users can only access their own cards
            entity.HasOne(e => e.User)
                .WithMany(u => u.StoredCreditCards)
                .HasForeignKey(e => e.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            // Index for faster lookups
            // Step 5: Index on UserId improves query performance for parameterized queries
            entity.HasIndex(e => e.UserId);
        });
    }
}

// ============================================================
// STEP 5: SQL SERVER STORED PROCEDURES FOR PRODUCTION
// ============================================================
//
// These stored procedures should be created in SQL Server for Step 3 implementation:
//
// -- sp_GetUserCreditCards: Safely retrieves user's saved cards
// CREATE PROCEDURE sp_GetUserCreditCards
//     @UserId NVARCHAR(450)
// AS
// BEGIN
//     SET NOCOUNT ON;
//     SELECT Id, CardBrand, LastFourDigits, ExpiryMonth, ExpiryYear
//     FROM StoredCreditCards
//     WHERE UserId = @UserId
//     ORDER BY CreatedAt DESC;
// END
// GO
//
// -- sp_SaveCreditCard: Safely inserts new card data
// CREATE PROCEDURE sp_SaveCreditCard
//     @UserId NVARCHAR(450),
//     @EncryptedCardNumber VARBINARY(MAX),
//     @CardBrand NVARCHAR(50),
//     @LastFourDigits NVARCHAR(4),
//     @CardholderName NVARCHAR(100),
//     @ExpiryMonth INT,
//     @ExpiryYear INT
// AS
// BEGIN
//     SET NOCOUNT ON;
//     INSERT INTO StoredCreditCards
//         (UserId, EncryptedCardNumber, CardBrand, LastFourDigits,
//          EncryptedCardholderName, ExpiryMonth, ExpiryYear, CreatedAt)
//     VALUES
//         (@UserId, @EncryptedCardNumber, @CardBrand, @LastFourDigits,
//          @CardholderName, @ExpiryMonth, @ExpiryYear, GETUTCDATE());
//
//     SELECT SCOPE_IDENTITY() AS NewId;
// END
// GO
//
// -- sp_DeleteCreditCard: Safely deletes a card (with ownership check)
// CREATE PROCEDURE sp_DeleteCreditCard
//     @CardId INT,
//     @UserId NVARCHAR(450)
// AS
// BEGIN
//     SET NOCOUNT ON;
//     DELETE FROM StoredCreditCards
//     WHERE Id = @CardId AND UserId = @UserId;
//
//     SELECT @@ROWCOUNT AS RowsAffected;
// END
// GO
