using DH.Permissions.Identity.JwtBearer;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Options;

using NewLife;
using NewLife.Log;
using NewLife.Serialization;

using Pek;
using Pek.Security;

namespace DH.Permissions.Authorization.Policies;

/// <summary>
/// Jwt授权处理器
/// </summary>
public class JsonWebTokenAuthorizationHandler : AuthorizationHandler<JsonWebTokenAuthorizationRequirement>
{
    /// <summary>
    /// Jwt选项配置
    /// </summary>
    private readonly JwtOptions _options;

    /// <summary>
    /// Jwt令牌校验器
    /// </summary>
    private readonly IJsonWebTokenValidator _tokenValidator;

    /// <summary>
    /// Jwt令牌存储器
    /// </summary>
    private readonly IJsonWebTokenStore _tokenStore;

    private readonly IHttpContextAccessor _accessor;

    /// <summary>
    /// 初始化一个<see cref="JsonWebTokenAuthorizationHandler"/>类型的实例
    /// </summary>
    /// <param name="options">Jwt选项配置</param>
    /// <param name="tokenValidator">Jwt令牌校验器</param>
    /// <param name="tokenStore">Jwt令牌存储器</param>
    /// <param name="accessor">HttpContext</param>
    public JsonWebTokenAuthorizationHandler(
        IHttpContextAccessor accessor
        , IOptions<JwtOptions> options
        , IJsonWebTokenValidator tokenValidator
        , IJsonWebTokenStore tokenStore)
    {
        _options = options.Value;
        _tokenValidator = tokenValidator;
        _tokenStore = tokenStore;
        _accessor = accessor;
    }

    /// <summary>
    /// 重载异步处理
    /// </summary>
    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, JsonWebTokenAuthorizationRequirement requirement)
    {
        if (_options.ThrowEnabled)
        {
            ThrowExceptionHandle(context, requirement);
            return;
        }
        ResultHandle(context, requirement);
        await Task.FromResult(0);
    }

    /// <summary>
    /// 抛异常处理方式
    /// </summary>
    protected virtual void ThrowExceptionHandle(AuthorizationHandlerContext context,
        JsonWebTokenAuthorizationRequirement requirement)
    {
        XTrace.WriteLine($"进来这里了么？ThrowExceptionHandle");
        var httpContext = (context.Resource as AuthorizationFilterContext)?.HttpContext;
        if (httpContext == null)
            return;
        // 未登录而被拒绝
        var result = httpContext.Request.Headers.TryGetValue("Authorization", out var authorizationHeader);
        if (!result || string.IsNullOrWhiteSpace(authorizationHeader))
            throw new UnauthorizedAccessException("未授权，请传递Header头的Authorization参数");
        var token = authorizationHeader.ToString().Split(' ').Last().Trim();
        if (!_tokenStore.ExistsToken(token))
            throw new UnauthorizedAccessException("未授权，无效参数");
        if (!_tokenValidator.Validate(token, _options, requirement.ValidatePayload))
            throw new UnauthorizedAccessException("验证失败，请查看传递的参数是否正确或是否有权限访问该地址。");
        if (_options.SingleDeviceEnabled)
        {
            var payload = GetPayload(token);
            var bindDeviceInfo = _tokenStore.GetUserDeviceToken(payload["sub"].SafeString(), payload["clientType"].SafeString());
            if (bindDeviceInfo.DeviceId != payload["clientId"].SafeString())
                throw new UnauthorizedAccessException("该账号已在其它设备登录");
        }
        var isAuthenticated = httpContext.User.Identity.IsAuthenticated;
        if (!isAuthenticated)
            return;
        context.Succeed(requirement);
    }

    /// <summary>
    /// 结果处理方式
    /// </summary>
    protected virtual void ResultHandle(AuthorizationHandlerContext context,
        JsonWebTokenAuthorizationRequirement requirement)
    {
        XTrace.WriteLine($"进来这里了么？ResultHandle");
        var httpContext = _accessor.HttpContext;

        if (httpContext == null)
            httpContext = Pek.Webs.HttpContext.Current;
        if (httpContext == null)
            return;

        // 未登录而被拒绝
        var result = httpContext.Request.Headers.TryGetValue("Authorization", out var authorizationHeader);
        XTrace.WriteLine($"进来这里了么1？ResultHandle");
        if (!result || String.IsNullOrWhiteSpace(authorizationHeader))
        {
            context.Fail();
            return;
        }
        XTrace.WriteLine($"进来这里了么2？ResultHandle");
        var token = authorizationHeader.ToString().Split(' ').Last().Trim();
        if (!_tokenStore.ExistsToken(token))
        {
            context.Fail();
            return;
        }
        XTrace.WriteLine($"进来这里了么3？ResultHandle");
        if (!_tokenValidator.Validate(token, _options, requirement.ValidatePayload))
        {
            context.Fail();
            return;
        }
        XTrace.WriteLine($"进来这里了么4？ResultHandle");
        // 登录超时
        var accessToken = _tokenStore.GetToken(token);
        if (accessToken.IsExpired())
        {
            context.Fail();
            return;
        }
        XTrace.WriteLine($"进来这里了么5？ResultHandle");
        var payload = GetPayload(token);

        // 单设备登录
        if (_options.SingleDeviceEnabled)
        {
            var bindDeviceInfo = _tokenStore.GetUserDeviceToken(payload["sub"].SafeString(), payload["clientType"].SafeString());
            if (bindDeviceInfo.DeviceId != payload["clientId"].SafeString())
            {
                context.Fail();
                return;
            }
        }
        XTrace.WriteLine($"进来这里了么6？ResultHandle");

        var isAuthenticated = httpContext.User.Identity.IsAuthenticated;
        if (!isAuthenticated)
            return;
        XTrace.WriteLine($"进来这里了么7？ResultHandle");
        httpContext.Items["clientId"] = payload["clientId"];

        context.Succeed(requirement);
    }

    /// <summary>
    /// 获取Payload
    /// </summary>
    /// <param name="encodeJwt">加密后的Jwt令牌</param>
    private IDictionary<String, Object> GetPayload(String encodeJwt)
    {
        var jwtArray = encodeJwt.Split('.');
        if (jwtArray.Length < 3)
            throw new ArgumentException($"非有效Jwt令牌");
        var payload = jwtArray[1].ToBase64().ToStr().DecodeJson();
        return payload;
    }
}
