using System.Security.Claims;
using System.Text.Encodings.Web;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

using NewLife;
using NewLife.Web;

using Pek.Permissions.Authorization;
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

        if (!Request.Headers.TryGetValue("Authorization", out var authorizationHeader))
        {
            var query = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(Request.QueryString.Value);
            if (!query.TryGetValue("access_token", out authorizationHeader))
            {
                return AuthenticateResult.NoResult();
            }
        }

        var token = authorizationHeader.ToString().Replace("Bearer ", String.Empty).Trim();

        if (token.IsNullOrWhiteSpace()) return AuthenticateResult.NoResult();

        // 解码令牌
        var ss = _jwtOptions.Secret.Split(':');
        if (ss.Length < 2) return AuthenticateResult.Fail("Invalid secret format.");

        var jwt = new JwtBuilder
        {
            Algorithm = ss[0],
            Secret = ss[1],
        };

        if (!jwt.TryDecode(token, out _)) return AuthenticateResult.Fail("Invalid token signature.");

        var claims = Helper.ToClaims(jwt.Items);
        var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(claims, "jwt"));

        Context.Items["jwt-Authorization"] = token;

        await Task.CompletedTask.ConfigureAwait(false);

        var ticket = new AuthenticationTicket(claimsPrincipal, Scheme.Name);
        return AuthenticateResult.Success(ticket);
    }

    /// <summary>
    /// 处理认证挑战（401 未授权）
    /// </summary>
    /// <param name="properties">认证属性</param>
    /// <returns></returns>
    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = 401;
        Response.ContentType = "application/json; charset=utf-8";

        // 从 HttpContext 中获取具体的失败原因和错误码
        var failureReason = Context.Items["AuthFailureReason"]?.ToString();
        var failureCode = Context.Items["AuthFailureCode"];

        var result = new AuthorizeResult();
        result.Message = failureReason ?? "未授权访问，请先登录";
        result.ErrCode = failureCode is int code ? code : 40001;

        await result.ExecuteResultAsync(new ActionContext
        {
            HttpContext = Context
        }).ConfigureAwait(false);
    }

    /// <summary>
    /// 处理禁止访问（403 权限不足）
    /// </summary>
    /// <param name="properties">认证属性</param>
    /// <returns></returns>
    protected override async Task HandleForbiddenAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = 403;
        Response.ContentType = "application/json; charset=utf-8";

        // 从 HttpContext 中获取具体的失败原因和错误码
        var failureReason = Context.Items["AuthFailureReason"]?.ToString();
        var failureCode = Context.Items["AuthFailureCode"];

        var result = new AuthorizeResult();
        result.Message = failureReason ?? "权限不足，禁止访问";
        result.ErrCode = failureCode is int code ? code : 40301;

        await result.ExecuteResultAsync(new ActionContext
        {
            HttpContext = Context
        }).ConfigureAwait(false);
    }
}
