using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Http;

namespace Pr3.ConfigAndSecurity.Middlewares;

public static class RequestId
{
    private const string ItemKey = "request_id";
    private const string HeaderName = "X-Request-Id";
    private static readonly Regex Allowed = new(@"^[a-zA-Z0-9\-]{1,64}$", RegexOptions.Compiled);

    public static string GetOrCreate(HttpContext context)
    {
        if (context.Items.TryGetValue(ItemKey, out var existing) && existing is string s && s.Length > 0)
            return s;

        var candidate = context.Request.Headers[HeaderName].FirstOrDefault();
        var requestId = !string.IsNullOrWhiteSpace(candidate) && Allowed.IsMatch(candidate!)
            ? candidate!
            : Guid.NewGuid().ToString("N");

        context.Items[ItemKey] = requestId;
        context.Response.Headers[HeaderName] = requestId;

        return requestId;
    }
}
