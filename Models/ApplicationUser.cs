using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;

namespace SecureWebApp.Models;

/// <summary>
/// Custom user class extending IdentityUser with additional properties.
/// The base IdentityUser already includes:
/// - AccessFailedCount (for account lockout - Section 1.1)
/// - LockoutEnd (for account lockout - Section 1.1)
/// - LockoutEnabled (for account lockout - Section 1.1)
/// - PasswordHash (for secure password storage - Section 1.2)
/// </summary>
public class ApplicationUser : IdentityUser
{
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? LastLoginAt { get; set; }

    // Navigation property for stored credit cards
    public virtual ICollection<StoredCreditCard> StoredCreditCards { get; set; } = new List<StoredCreditCard>();
}