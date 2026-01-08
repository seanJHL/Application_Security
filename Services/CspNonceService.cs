using System.Security.Cryptography;

namespace SecureWebApp.Services;

/// <summary>
/// Service for generating and managing Content Security Policy (CSP) nonces.
/// Nonces provide XSS protection by allowing only scripts/styles with matching nonce values.
/// This replaces 'unsafe-inline' in CSP headers for stronger security.
/// </summary>
public interface ICspNonceService
{
    /// <summary>
    /// Gets the current request's nonce value for use in script/style tags
    /// </summary>
    string GetNonce();

    /// <summary>
    /// Gets the CSP header value with the current nonce
    /// </summary>
    string GetCspHeaderValue();
}

public class CspNonceService : ICspNonceService
{
    private readonly string _nonce;

    public CspNonceService()
    {
        // Generate a cryptographically secure random nonce for this request
        // Using 32 bytes (256 bits) for strong security
        _nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
    }

    public string GetNonce() => _nonce;

    public string GetCspHeaderValue()
    {
        // Build CSP with nonce-based script and style sources
        // This blocks inline script execution unless it has the correct nonce
        return string.Join(" ",
            "default-src 'self';",
            $"script-src 'self' 'nonce-{_nonce}' https://cdn.jsdelivr.net;",
            $"style-src 'self' 'nonce-{_nonce}' https://cdn.jsdelivr.net;",
            "img-src 'self' data:;",
            "font-src 'self' https://cdn.jsdelivr.net;",
            "frame-ancestors 'none';",
            "form-action 'self';",
            "base-uri 'self';",
            "object-src 'none';",
            "upgrade-insecure-requests;"
        );
    }
}
