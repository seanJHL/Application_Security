using System.Text.RegularExpressions;
using System.Web;

namespace SecureWebApp.Services;

/// <summary>
/// XSS PROTECTION LAYER 5: HTML Sanitizer Service
///
/// Use this service ONLY when you must allow some HTML content from users.
/// For most cases, use Razor's automatic output encoding (@Model.Property).
///
/// IMPORTANT: NEVER use Html.Raw() with unsanitized user data!
/// If you must render HTML, ALWAYS sanitize it first with this service.
///
/// Example usage:
///     var safeHtml = _sanitizer.Sanitize(userInput);
///     @Html.Raw(safeHtml)  // Only safe after sanitization
/// </summary>
public interface IHtmlSanitizerService
{
    /// <summary>
    /// Sanitizes HTML content using a whitelist approach.
    /// Only allows safe tags and attributes; strips all scripts and event handlers.
    /// </summary>
    /// <param name="html">The potentially unsafe HTML content</param>
    /// <returns>Sanitized HTML safe for rendering</returns>
    string Sanitize(string html);

    /// <summary>
    /// Completely strips all HTML tags, returning only text content.
    /// Use this when no HTML should be preserved.
    /// </summary>
    /// <param name="html">HTML content to strip</param>
    /// <returns>Plain text with all HTML removed</returns>
    string StripAllHtml(string html);

    /// <summary>
    /// Encodes text for safe HTML output.
    /// Converts special characters to HTML entities.
    /// </summary>
    /// <param name="text">Text to encode</param>
    /// <returns>HTML-encoded text</returns>
    string HtmlEncode(string text);
}

public class HtmlSanitizerService : IHtmlSanitizerService
{
    // ============================================================
    // WHITELIST CONFIGURATION
    // Only these tags and attributes are allowed through sanitization
    // ============================================================

    // Safe HTML tags that cannot execute scripts
    private static readonly HashSet<string> AllowedTags = new(StringComparer.OrdinalIgnoreCase)
    {
        // Text formatting
        "p", "br", "hr",
        "b", "strong", "i", "em", "u", "s", "strike",
        "sub", "sup", "small", "mark",

        // Headers
        "h1", "h2", "h3", "h4", "h5", "h6",

        // Lists
        "ul", "ol", "li",

        // Block elements
        "div", "span", "blockquote", "pre", "code",

        // Tables (basic)
        "table", "thead", "tbody", "tfoot", "tr", "th", "td",

        // Links (href will be validated separately)
        "a"
    };

    // Safe attributes that cannot execute scripts
    private static readonly HashSet<string> AllowedAttributes = new(StringComparer.OrdinalIgnoreCase)
    {
        "class", "id", "title", "alt",
        "colspan", "rowspan",
        "href" // Will be validated for safe protocols
    };

    // Safe URL protocols for href attributes
    private static readonly HashSet<string> AllowedProtocols = new(StringComparer.OrdinalIgnoreCase)
    {
        "http", "https", "mailto"
    };

    // Regex patterns for sanitization
    private static readonly Regex HtmlTagPattern = new(
        @"<(/?)(\w+)([^>]*)>",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex AttributePattern = new(
        @"(\w+)\s*=\s*(?:""([^""]*)""|'([^']*)'|([^\s>]+))",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex StripHtmlPattern = new(
        @"<[^>]*>",
        RegexOptions.Compiled);

    // Dangerous patterns that should never pass through
    private static readonly Regex DangerousPatterns = new(
        @"(javascript|vbscript|data)\s*:|expression\s*\(|on\w+\s*=",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public string Sanitize(string html)
    {
        if (string.IsNullOrEmpty(html))
            return string.Empty;

        // First pass: check for dangerous patterns and reject if found
        if (DangerousPatterns.IsMatch(html))
        {
            // Log this attempt and return encoded version instead
            return HtmlEncode(html);
        }

        // Second pass: process each HTML tag
        var sanitized = HtmlTagPattern.Replace(html, match =>
        {
            var isClosing = match.Groups[1].Value == "/";
            var tagName = match.Groups[2].Value.ToLowerInvariant();
            var attributesPart = match.Groups[3].Value;

            // Check if tag is in whitelist
            if (!AllowedTags.Contains(tagName))
            {
                // Strip disallowed tags entirely
                return string.Empty;
            }

            if (isClosing)
            {
                return $"</{tagName}>";
            }

            // Process attributes for allowed tags
            var safeAttributes = SanitizeAttributes(tagName, attributesPart);
            var isSelfClosing = attributesPart.TrimEnd().EndsWith("/");

            if (string.IsNullOrEmpty(safeAttributes))
            {
                return isSelfClosing ? $"<{tagName} />" : $"<{tagName}>";
            }

            return isSelfClosing ? $"<{tagName} {safeAttributes} />" : $"<{tagName} {safeAttributes}>";
        });

        return sanitized;
    }

    private string SanitizeAttributes(string tagName, string attributesPart)
    {
        if (string.IsNullOrWhiteSpace(attributesPart))
            return string.Empty;

        var safeAttributes = new List<string>();

        foreach (Match match in AttributePattern.Matches(attributesPart))
        {
            var attrName = match.Groups[1].Value.ToLowerInvariant();
            var attrValue = match.Groups[2].Success ? match.Groups[2].Value :
                           match.Groups[3].Success ? match.Groups[3].Value :
                           match.Groups[4].Value;

            // Skip disallowed attributes
            if (!AllowedAttributes.Contains(attrName))
                continue;

            // Special handling for href attribute
            if (attrName == "href")
            {
                if (!IsAllowedUrl(attrValue))
                    continue;

                // Encode the URL value
                attrValue = HttpUtility.HtmlAttributeEncode(attrValue);
            }
            else
            {
                // Check attribute value for dangerous content
                if (DangerousPatterns.IsMatch(attrValue))
                    continue;

                attrValue = HttpUtility.HtmlAttributeEncode(attrValue);
            }

            safeAttributes.Add($"{attrName}=\"{attrValue}\"");
        }

        return string.Join(" ", safeAttributes);
    }

    private bool IsAllowedUrl(string url)
    {
        if (string.IsNullOrWhiteSpace(url))
            return false;

        url = url.Trim();

        // Allow relative URLs
        if (url.StartsWith("/") || url.StartsWith("./") || url.StartsWith("../"))
            return true;

        // Allow fragment-only URLs
        if (url.StartsWith("#"))
            return true;

        // Check for allowed protocols
        var colonIndex = url.IndexOf(':');
        if (colonIndex == -1)
            return true; // No protocol specified, treat as relative

        var protocol = url.Substring(0, colonIndex).ToLowerInvariant();
        return AllowedProtocols.Contains(protocol);
    }

    public string StripAllHtml(string html)
    {
        if (string.IsNullOrEmpty(html))
            return string.Empty;

        // Remove all HTML tags
        var stripped = StripHtmlPattern.Replace(html, string.Empty);

        // Decode HTML entities
        stripped = HttpUtility.HtmlDecode(stripped);

        return stripped.Trim();
    }

    public string HtmlEncode(string text)
    {
        if (string.IsNullOrEmpty(text))
            return string.Empty;

        return HttpUtility.HtmlEncode(text);
    }
}
