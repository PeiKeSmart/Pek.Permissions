using System.Security.Claims;
using System.Text.Encodings.Web;

using DH.Permissions.Identity.JwtBearer.Internal;

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

using NewLife;
using NewLife.Web;

using Pek.Permissions.Identity.Options;
using Pek.Security;

namespace Pek.Permissions.Identity.JwtBearer.Internal;

public class PekJwtBearerHandler : AuthenticationHandler<PekJwtBearerOptions>
{
    private readonly JwtOptions _jwtOptions;

    public PekJwtBearerHandler(IOptionsMonitor<PekJwtBearerOptions> options, ILoggerFactory logger, UrlEncoder encoder, IOptions<JwtOptions> jwtOptions)
       : base(options, logger, encoder)
    {
        _jwtOptions = jwtOptions.Value;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (_jwtOptions.Secret.IsNullOrWhiteSpace()) return AuthenticateResult.Fail("Secret is null.");

        if (!Request.Headers.TryGetValue("Authorization", out var authorizationHeader)) return AuthenticateResult.NoResult();

        var token = authorizationHeader.ToString().Replace("Bearer ", String.Empty).Trim();

        if (token.IsNullOrWhiteSpace()) return AuthenticateResult.NoResult();

        // 解码令牌
        var ss = _jwtOptions.Secret.Split(':');
        var jwt = new JwtBuilder
        {
            Algorithm = ss[0],
            Secret = ss[1],
        };

        if (!jwt.TryDecode(token, out _)) return AuthenticateResult.Fail("Invalid token signature.");

        var claims = Helper.ToClaims(jwt.Items);
        var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(claims, "jwt"));

        Context.Items["jwt-Authorization"] = token;

        await Task.CompletedTask;

        var ticket = new AuthenticationTicket(claimsPrincipal, Scheme.Name);
        return AuthenticateResult.Success(ticket);
    }
}
