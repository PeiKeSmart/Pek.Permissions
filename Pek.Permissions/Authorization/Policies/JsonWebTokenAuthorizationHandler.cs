using DH.Permissions.Identity.JwtBearer;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Options;

using Pek;
using Pek.Helpers;
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
        var httpContext = (context.Resource as AuthorizationFilterContext)?.HttpContext;
        if (httpContext == null)
            return;
        // 未登录而被拒绝
        var authorizationHeader = httpContext.Items["jwt-Authorization"].SafeString();
        var token = authorizationHeader.Trim();
        if (!_tokenStore.ExistsToken(token))
            throw new UnauthorizedAccessException("未授权，无效参数");
        if (!_tokenValidator.Validate(token, _options, requirement.ValidatePayload))
            throw new UnauthorizedAccessException("验证失败，请查看传递的参数是否正确或是否有权限访问该地址。");
        if (_options.SingleDeviceEnabled)
        {
            var payload = DHWeb.HttpContext.Items["jwt-payload"] as IDictionary<String, Object>;
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
        var httpContext = _accessor.HttpContext;

        if (httpContext == null)
            httpContext = Pek.Webs.HttpContext.Current;
        if (httpContext == null)
            return;

        var authorizationHeader = httpContext.Items["jwt-Authorization"].SafeString();
        var token = authorizationHeader.Trim();
        if (!_tokenStore.ExistsToken(token))
        {
            context.Fail();
            return;
        }
        if (!_tokenValidator.Validate(token, _options, requirement.ValidatePayload))
        {
            context.Fail();
            return;
        }
        // 登录超时
        var accessToken = _tokenStore.GetToken(token);
        if (accessToken.IsExpired())
        {
            context.Fail();
            return;
        }
        var payload = DHWeb.HttpContext.Items["jwt-payload"] as IDictionary<String, Object>;

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

        var isAuthenticated = httpContext.User.Identity.IsAuthenticated;
        if (!isAuthenticated)
            return;
        httpContext.Items["clientId"] = payload["clientId"];

        context.Succeed(requirement);
    }
}
