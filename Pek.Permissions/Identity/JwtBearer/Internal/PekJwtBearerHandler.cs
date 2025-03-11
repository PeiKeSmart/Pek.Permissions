﻿using System.Security.Claims;
using System.Text.Encodings.Web;

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

using NewLife;
using NewLife.Log;
using NewLife.Serialization;
using NewLife.Web;

using Pek.Permissions.Identity.Options;
using Pek.Security;
using Pek.Webs;

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
        XTrace.WriteLine($"鉴权进来：PekJwtBearerHandler：{Request.GetRawUrl()}");
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

        XTrace.WriteLine($"鉴权进来：PekJwtBearerHandler：{token}:{jwt.TryDecode(token, out _)}");

        if (!jwt.TryDecode(token, out _)) return AuthenticateResult.Fail("Invalid token signature.");

        XTrace.WriteLine($"鉴权进来：PekJwtBearerHandler11111：{jwt.Items.ToJson()}");

        var claims = Helper.ToClaims(jwt.Items);
        if (claims == null || !claims.Any())
        {
            XTrace.WriteLine("No valid claims found in token.");
        }

        var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(claims, "jwt"));

        Context.Items["jwt-Authorization"] = token;

        await Task.CompletedTask.ConfigureAwait(false);

        var ticket = new AuthenticationTicket(claimsPrincipal, Scheme.Name);
        return AuthenticateResult.Success(ticket);
    }
}
