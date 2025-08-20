using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Options;

using NewLife;
using NewLife.Log;

using Pek.Configs;
using Pek.Helpers;
using Pek.Permissions.Identity.JwtBearer;
using Pek.Permissions.Security;
using Pek.Security;
using Pek.Webs;

namespace Pek.Permissions.Authorization.Policies;

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
        await Task.FromResult(0).ConfigureAwait(false);
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

        // 尝试从缓存获取Token信息，避免重复验证
        var cacheKey = $"CachedTokenInfo_{token.GetHashCode()}";
        CachedTokenInfo? cachedTokenInfo = null;
        if (httpContext.Items.TryGetValue(cacheKey, out var cachedObj) && cachedObj is CachedTokenInfo cached && cached.IsCacheValid)
        {
            cachedTokenInfo = cached;
        }

        if (!_tokenStore.ExistsToken(token))
            throw new UnauthorizedAccessException("未授权，无效参数");

        // 如果有缓存的Token信息且已验证过签名，跳过重复验证
        if (cachedTokenInfo?.IsSignatureValid != true)
        {
            if (!_tokenValidator.Validate(token, _options, requirement.ValidatePayload))
                throw new UnauthorizedAccessException("验证失败，请查看传递的参数是否正确或是否有权限访问该地址。");
        }
        else
        {
            // 使用缓存的Payload信息，只进行自定义验证
            if (cachedTokenInfo.Payload != null && !requirement.ValidatePayload(cachedTokenInfo.Payload, _options))
                throw new UnauthorizedAccessException("验证失败，请查看传递的参数是否正确或是否有权限访问该地址。");
        }

        // 获取Payload信息（优先使用缓存）
        var payload = cachedTokenInfo?.Payload ?? DHWeb.HttpContext.Items["jwt-payload"] as IDictionary<String, Object>;
        var endpoint = httpContext.GetEndpoint();
        var fromAttribute = endpoint?.Metadata.GetMetadata<JwtAuthorizeAttribute>();
        var requiredFrom = fromAttribute?.From;
        var tokenFrom = payload?.TryGetValue("From", out var fromObj) == true ? fromObj as String : String.Empty;
        if (!requiredFrom.IsNullOrWhiteSpace())
        {
            if (!String.Equals(tokenFrom, requiredFrom, StringComparison.OrdinalIgnoreCase))
            {
                throw new UnauthorizedAccessException($"Token来源不符，要求From={requiredFrom}, 实际From={tokenFrom}");
            }
        }

        // 设备ID验证：验证Token中的clientId与当前设备ID是否一致
        var currentDeviceId = DHWebHelper.FillDeviceId(httpContext);
        var tokenClientId = payload?.TryGetValue("clientId", out var clientIdObj) == true ? clientIdObj as String : String.Empty;
        var allowCrossDevice = PekSysSetting.Current.AllowJwtCrossDevice;

        if (!currentDeviceId.IsNullOrEmpty() && !tokenClientId.IsNullOrEmpty() && tokenClientId != currentDeviceId && !allowCrossDevice)
        {
            var userId = payload?.GetOrDefault("sub", "未知").ToString() ?? "未知";
            SecurityLogger.LogDeviceIdMismatch(httpContext, tokenClientId, currentDeviceId, userId, new { Action = "TokenValidation", Method = "ThrowException" });
            throw new UnauthorizedAccessException($"设备标识不匹配，Token无法在此设备使用");
        }
        else if (!currentDeviceId.IsNullOrEmpty() && !tokenClientId.IsNullOrEmpty() && tokenClientId != currentDeviceId && allowCrossDevice)
        {
            var userId = payload?.GetOrDefault("sub", "未知").ToString() ?? "未知";
            XTrace.WriteLine($"[开发模式] 允许跨设备Token验证: tokenClientId={tokenClientId}, currentDeviceId={currentDeviceId}, userId={userId}");
        }

        // 单设备登录验证
        if (_options.SingleDeviceEnabled && payload != null)
        {
            var bindDeviceInfo = _tokenStore.GetUserDeviceToken(payload["sub"].SafeString(), payload["clientType"].SafeString());
            if (bindDeviceInfo?.DeviceId != payload["clientId"].SafeString())
                throw new UnauthorizedAccessException("该账号已在其它设备登录");
        }
        var isAuthenticated = httpContext.User.Identity?.IsAuthenticated == true;
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

        // 尝试从缓存获取Token信息
        var cacheKey = $"CachedTokenInfo_{token.GetHashCode()}";
        CachedTokenInfo? cachedTokenInfo = null;
        if (httpContext.Items.TryGetValue(cacheKey, out var cachedObj) && cachedObj is CachedTokenInfo cached && cached.IsCacheValid)
        {
            cachedTokenInfo = cached;
        }

        // 获取Payload信息（优先使用缓存）
        var payload = cachedTokenInfo?.Payload ?? DHWeb.HttpContext.Items["jwt-payload"] as IDictionary<String, Object>;

        // 提取用户信息用于批量查询
        var userId = payload?.GetOrDefault("sub", "").ToString() ?? "";
        var clientType = payload?.GetOrDefault("clientType", "").ToString() ?? "";

        // 一次性获取完整Token信息，减少多次缓存查询
        var completeTokenInfo = _tokenStore.GetCompleteTokenInfo(token, userId, clientType);

        if (!completeTokenInfo.TokenExists)
        {
            // 设置具体的失败原因到 HttpContext，供 Challenge 处理器使用
            httpContext.Items["AuthFailureReason"] = "Token不存在或已失效";
            httpContext.Items["AuthFailureCode"] = 40001;
            context.Fail();
            return;
        }

        // 如果有缓存的Token信息且已验证过签名，跳过重复验证
        if (cachedTokenInfo?.IsSignatureValid != true)
        {
            if (!_tokenValidator.Validate(token, _options, requirement.ValidatePayload))
            {
                httpContext.Items["AuthFailureReason"] = "Token验证失败";
                httpContext.Items["AuthFailureCode"] = 40002;
                context.Fail();
                return;
            }
        }
        else
        {
            // 使用缓存的Payload信息，只进行自定义验证
            if (cachedTokenInfo.Payload != null && !requirement.ValidatePayload(cachedTokenInfo.Payload, _options))
            {
                httpContext.Items["AuthFailureReason"] = "Token验证失败";
                httpContext.Items["AuthFailureCode"] = 40002;
                context.Fail();
                return;
            }
        }

        // 检查Token是否过期
        if (completeTokenInfo.IsExpired)
        {
            httpContext.Items["AuthFailureReason"] = "Token已过期";
            httpContext.Items["AuthFailureCode"] = 40003;
            context.Fail();
            return;
        }

        // 兼容旧版本：校验From字段
        var endpoint = httpContext.GetEndpoint();
        var fromAttribute = endpoint?.Metadata.GetMetadata<JwtAuthorizeAttribute>();
        var requiredFrom = fromAttribute?.From;
        var tokenFrom = payload?.TryGetValue("From", out var fromObj) == true ? fromObj as String : String.Empty;
        if (!requiredFrom.IsNullOrWhiteSpace())
        {
            if (!String.Equals(tokenFrom, requiredFrom, StringComparison.OrdinalIgnoreCase))
            {
                httpContext.Items["AuthFailureReason"] = $"Token来源不符，要求From={requiredFrom}，实际From={tokenFrom}";
                httpContext.Items["AuthFailureCode"] = 40301;
                context.Fail();
                return;
            }
        }

        // 设备ID验证：验证Token中的clientId与当前设备ID是否一致
        var currentDeviceId = DHWebHelper.FillDeviceId(httpContext);
        var tokenClientId = payload?.TryGetValue("clientId", out var clientIdObj) == true ? clientIdObj as String : String.Empty;
        var allowCrossDevice = PekSysSetting.Current.AllowJwtCrossDevice;

        if (!currentDeviceId.IsNullOrEmpty() && !tokenClientId.IsNullOrEmpty() && tokenClientId != currentDeviceId && !allowCrossDevice)
        {
            var userIdForLog = completeTokenInfo.UserId.IsNullOrEmpty() ? "未知" : completeTokenInfo.UserId;
            SecurityLogger.LogDeviceIdMismatch(httpContext, tokenClientId, currentDeviceId, userIdForLog, new { Action = "TokenValidation", Method = "ResultHandle" });
            httpContext.Items["AuthFailureReason"] = "设备标识不匹配，Token无法在此设备使用";
            httpContext.Items["AuthFailureCode"] = 40005;
            context.Fail();
            return;
        }
        else if (!currentDeviceId.IsNullOrEmpty() && !tokenClientId.IsNullOrEmpty() && tokenClientId != currentDeviceId && allowCrossDevice)
        {
            var userIdForLog = completeTokenInfo.UserId.IsNullOrEmpty() ? "未知" : completeTokenInfo.UserId;
            XTrace.WriteLine($"[开发模式] 允许跨设备Token验证: tokenClientId={tokenClientId}, currentDeviceId={currentDeviceId}, userId={userIdForLog}");
        }

        // 单设备登录验证（使用批量查询的结果）
        if (_options.SingleDeviceEnabled && completeTokenInfo.DeviceBindInfo != null && payload != null)
        {
            var payloadDeviceId = payload["clientId"].SafeString();
            if (completeTokenInfo.DeviceBindInfo.DeviceId != payloadDeviceId)
            {
                httpContext.Items["AuthFailureReason"] = "该账号已在其它设备登录";
                httpContext.Items["AuthFailureCode"] = 40004;
                context.Fail();
                return;
            }
        }

        var isAuthenticated = httpContext.User.Identity?.IsAuthenticated == true;
        if (!isAuthenticated)
            return;

        if (payload?.ContainsKey("clientId") == true)
        {
            httpContext.Items["clientId"] = payload["clientId"];
        }

        context.Succeed(requirement);
    }
}
