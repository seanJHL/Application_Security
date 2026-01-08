using Microsoft.AspNetCore.Razor.TagHelpers;
using SecureWebApp.Services;

namespace SecureWebApp.TagHelpers;

/// <summary>
/// XSS PROTECTION: Tag helper that automatically adds CSP nonces to script and style tags.
///
/// This enables Content Security Policy protection while allowing inline scripts/styles.
/// Without the correct nonce, inline scripts will be blocked by the browser.
///
/// Usage:
///   <script csp-nonce>
///     // Your inline JavaScript here
///   </script>
///
///   <style csp-nonce>
///     /* Your inline CSS here */
///   </style>
///
/// The nonce value is automatically injected and matches the CSP header.
/// </summary>
[HtmlTargetElement("script", Attributes = "csp-nonce")]
[HtmlTargetElement("style", Attributes = "csp-nonce")]
public class CspNonceTagHelper : TagHelper
{
    private readonly ICspNonceService _cspNonceService;

    public CspNonceTagHelper(ICspNonceService cspNonceService)
    {
        _cspNonceService = cspNonceService;
    }

    /// <summary>
    /// When present, adds the CSP nonce to this element
    /// </summary>
    [HtmlAttributeName("csp-nonce")]
    public bool CspNonce { get; set; }

    public override void Process(TagHelperContext context, TagHelperOutput output)
    {
        if (CspNonce)
        {
            var nonce = _cspNonceService.GetNonce();
            output.Attributes.SetAttribute("nonce", nonce);
        }

        // Remove the csp-nonce attribute from the output
        output.Attributes.RemoveAll("csp-nonce");
    }
}

/// <summary>
/// Tag helper that automatically adds CSP nonces to all inline script tags
/// without requiring the csp-nonce attribute.
///
/// This processes ALL script tags that don't have a src attribute,
/// automatically adding the nonce for CSP compliance.
/// </summary>
[HtmlTargetElement("script", Attributes = "!src")]
public class AutoCspNonceScriptTagHelper : TagHelper
{
    private readonly ICspNonceService _cspNonceService;

    public AutoCspNonceScriptTagHelper(ICspNonceService cspNonceService)
    {
        _cspNonceService = cspNonceService;
    }

    // Run after other tag helpers
    public override int Order => 1000;

    public override void Process(TagHelperContext context, TagHelperOutput output)
    {
        // Skip if already has a nonce
        if (output.Attributes.ContainsName("nonce"))
            return;

        // Add nonce to inline scripts
        var nonce = _cspNonceService.GetNonce();
        output.Attributes.SetAttribute("nonce", nonce);
    }
}

/// <summary>
/// Tag helper that automatically adds CSP nonces to all inline style tags.
/// </summary>
[HtmlTargetElement("style")]
public class AutoCspNonceStyleTagHelper : TagHelper
{
    private readonly ICspNonceService _cspNonceService;

    public AutoCspNonceStyleTagHelper(ICspNonceService cspNonceService)
    {
        _cspNonceService = cspNonceService;
    }

    // Run after other tag helpers
    public override int Order => 1000;

    public override void Process(TagHelperContext context, TagHelperOutput output)
    {
        // Skip if already has a nonce
        if (output.Attributes.ContainsName("nonce"))
            return;

        // Add nonce to inline styles
        var nonce = _cspNonceService.GetNonce();
        output.Attributes.SetAttribute("nonce", nonce);
    }
}
