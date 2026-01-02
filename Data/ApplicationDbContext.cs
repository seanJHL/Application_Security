using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using SecureWebApp.Models;

namespace SecureWebApp.Data;

public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    // Credit card storage table (Section 2.1)
    public DbSet<StoredCreditCard> StoredCreditCards { get; set; }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        // Configure StoredCreditCard entity
        builder.Entity<StoredCreditCard>(entity =>
        {
            entity.HasKey(e => e.Id);

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
            entity.HasOne(e => e.User)
                .WithMany(u => u.StoredCreditCards)
                .HasForeignKey(e => e.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            // Index for faster lookups
            entity.HasIndex(e => e.UserId);
        });
    }
}