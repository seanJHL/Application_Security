using Konscious.Security.Cryptography;
using Microsoft.AspNetCore.Identity;
using System;
using System.Security.Cryptography;
using System.Text;

namespace SecureWebApp.Services;

/// <summary>
/// Custom password hasher using Argon2id algorithm (Section 1.2)
/// Argon2id is the winner of the Password Hashing Competition
/// and provides protection against GPU-based attacks
/// </summary>
public class Argon2PasswordHasher<TUser> : IPasswordHasher<TUser> where TUser : class
{
    private const int SaltSize = 16;        // 128 bits
    private const int HashSize = 32;        // 256 bits
    private const int Iterations = 4;       // Time cost
    private const int MemorySize = 65536;   // 64 MB memory cost
    private const int Parallelism = 2;      // Degree of parallelism

    /// <summary>
    /// Hash a password using Argon2id
    /// </summary>
    public string HashPassword(TUser user, string password)
    {
        // Generate cryptographically secure random salt
        byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);

        // Hash password with Argon2id
        byte[] hash = HashWithArgon2(password, salt);

        // Combine salt and hash for storage
        byte[] hashBytes = new byte[SaltSize + HashSize];
        Array.Copy(salt, 0, hashBytes, 0, SaltSize);
        Array.Copy(hash, 0, hashBytes, SaltSize, HashSize);

        return Convert.ToBase64String(hashBytes);
    }

    /// <summary>
    /// Verify a password against a stored hash
    /// </summary>
    public PasswordVerificationResult VerifyHashedPassword(
        TUser user, string hashedPassword, string providedPassword)
    {
        try
        {
            byte[] hashBytes = Convert.FromBase64String(hashedPassword);

            // Ensure the hash is the expected length
            if (hashBytes.Length != SaltSize + HashSize)
            {
                return PasswordVerificationResult.Failed;
            }

            // Extract salt from stored hash
            byte[] salt = new byte[SaltSize];
            Array.Copy(hashBytes, 0, salt, 0, SaltSize);

            // Hash the provided password with the extracted salt
            byte[] computedHash = HashWithArgon2(providedPassword, salt);

            // Extract stored hash for comparison
            byte[] storedHash = new byte[HashSize];
            Array.Copy(hashBytes, SaltSize, storedHash, 0, HashSize);

            // Constant-time comparison to prevent timing attacks
            if (CryptographicOperations.FixedTimeEquals(computedHash, storedHash))
            {
                return PasswordVerificationResult.Success;
            }

            return PasswordVerificationResult.Failed;
        }
        catch
        {
            return PasswordVerificationResult.Failed;
        }
    }

    /// <summary>
    /// Perform Argon2id hashing
    /// </summary>
    private byte[] HashWithArgon2(string password, byte[] salt)
    {
        using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password));
        argon2.Salt = salt;
        argon2.Iterations = Iterations;
        argon2.MemorySize = MemorySize;
        argon2.DegreeOfParallelism = Parallelism;

        return argon2.GetBytes(HashSize);
    }
}