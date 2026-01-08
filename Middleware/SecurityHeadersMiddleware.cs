using System.Threading.Tasks;
using SecureWebApp.Services;

namespace SecureWebApp.Middleware;

/// <summary>
/// Middleware to add security headers to all responses (Section 2.3)
/// Implements protection against clickjacking, XSS, MIME sniffing, etc.
///
/// XSS PROTECTION LAYER 2: Content Security Policy (CSP)
/// - Uses nonce-based CSP instead of 'unsafe-inline' for stronger XSS protection
/// - Blocks inline script execution unless script has correct nonce
/// - Combined with Razor's automatic output encoding provides defense-in-depth
/// </summary>
public class SecurityHeadersMiddleware
{
    private readonly RequestDelegate _next;

    public SecurityHeadersMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Get the CSP nonce service for this request
        var cspNonceService = context.RequestServices.GetService<ICspNonceService>();

        var headers = context.Response.Headers;

        // Prevent clickjacking - don't allow page to be framed
        headers["X-Frame-Options"] = "DENY";

        // Prevent MIME-type sniffing - stops browsers from interpreting files as different MIME types
        headers["X-Content-Type-Options"] = "nosniff";

        // XSS filter for legacy browsers (deprecated but still useful for older browsers)
        // Modern browsers use CSP instead
        headers["X-XSS-Protection"] = "1; mode=block";

        // Control referrer information - prevents leaking sensitive URL data
        headers["Referrer-Policy"] = "strict-origin-when-cross-origin";

        // Permissions policy - disable unnecessary browser features to reduce attack surface
        headers["Permissions-Policy"] = "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()";

        // ============================================================
        // XSS PROTECTION: Content Security Policy with Nonces
        // ============================================================
        // Using nonce-based CSP instead of 'unsafe-inline' for XSS protection:
        // - 'nonce-{value}' allows only scripts/styles with matching nonce attribute
        // - Blocks execution of injected inline scripts even if they bypass other defenses
        // - Nonce changes per request, making it impossible for attackers to predict
        if (cspNonceService != null)
        {
            headers["Content-Security-Policy"] = cspNonceService.GetCspHeaderValue();
        }
        else
        {
            // Fallback CSP without nonces (stricter - no inline scripts at all)
            headers["Content-Security-Policy"] =
                "default-src 'self'; " +
                "script-src 'self' https://cdn.jsdelivr.net; " +
                "style-src 'self' https://cdn.jsdelivr.net; " +
                "img-src 'self' data:; " +
                "font-src 'self' https://cdn.jsdelivr.net; " +
                "frame-ancestors 'none'; " +
                "form-action 'self'; " +
                "base-uri 'self'; " +
                "object-src 'none'; " +
                "upgrade-insecure-requests;";
        }

        // Cache control for sensitive pages (payment pages)
        // Prevents sensitive data from being cached
        if (context.Request.Path.StartsWithSegments("/Payment") ||
            context.Request.Path.StartsWithSegments("/Account"))
        {
            headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private";
            headers["Pragma"] = "no-cache";
            headers["Expires"] = "0";
        }

        await _next(context);
    }
}