using System.Security.Claims;
using System.Text.Encodings.Web;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

using NewLife;
using NewLife.Web;
using NewLife.Serialization;

using Pek.Permissions.Authorization;
using Pek.Permissions.Identity.JwtBearer;
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

        // 优化Token提取，避免不必要的字符串操作
        var authHeaderStr = authorizationHeader.ToString();
        var token = authHeaderStr.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
            ? authHeaderStr.Substring(7).Trim()
            : authHeaderStr.Trim();

        if (token.IsNullOrWhiteSpace()) return AuthenticateResult.NoResult();

        // 检查是否已有缓存的Token信息
        var cacheKey = CachedTokenInfo.GetCacheKey(token);
        if (Context.Items.TryGetValue(cacheKey, out var cachedObj) && cachedObj is CachedTokenInfo cachedInfo && cachedInfo.IsCacheValid)
        {
            // 使用缓存的Token信息
            Context.Items["jwt-Authorization"] = token;
            Context.Items["jwt-header"] = cachedInfo.Header;
            Context.Items["jwt-payload"] = cachedInfo.Payload;

            await Task.CompletedTask.ConfigureAwait(false);
            return AuthenticateResult.Success(new AuthenticationTicket(cachedInfo.ClaimsPrincipal, Scheme.Name));
        }

        // 预先分割Token，避免重复操作
        var jwtArray = token.Split('.');
        if (jwtArray.Length < 3) return AuthenticateResult.Fail("Invalid token format.");

        // 使用工厂方法创建JWT构建器
        var jwt = JwtBuilderFactory.CreateBuilder(_jwtOptions.Secret);
        if (jwt == null) return AuthenticateResult.Fail("Invalid secret format.");

        if (!jwt.TryDecode(token, out _)) return AuthenticateResult.Fail("Invalid token signature.");

        // 直接使用jwt.Items中的解码结果，避免重复解析
        var claims = Helper.ToClaims(jwt.Items);
        var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(claims, "jwt"));

        // 解析Header和Payload（用于缓存和后续使用）
        var header = jwtArray[0].ToBase64().ToStr().DecodeJson();
        var payload = jwtArray[1].ToBase64().ToStr().DecodeJson();

        // 创建并缓存Token信息
        var tokenInfo = new CachedTokenInfo
        {
            Token = token,
            JwtBuilder = jwt,
            ClaimsPrincipal = claimsPrincipal,
            Header = header,
            Payload = payload,
            IsSignatureValid = true,
            DecodedAt = DateTime.UtcNow
        };

        Context.Items[cacheKey] = tokenInfo;
        Context.Items["jwt-Authorization"] = token;
        Context.Items["jwt-header"] = header;
        Context.Items["jwt-payload"] = payload;

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
