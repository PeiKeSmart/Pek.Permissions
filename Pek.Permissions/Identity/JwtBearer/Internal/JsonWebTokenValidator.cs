using NewLife;
using NewLife.Serialization;
using NewLife.Web;

using Pek.Helpers;
using Pek.Security;

namespace Pek.Permissions.Identity.JwtBearer.Internal;

/// <summary>
/// Jwt令牌校验器
/// </summary>
internal sealed class JsonWebTokenValidator : IJsonWebTokenValidator
{
    /// <summary>
    /// 校验
    /// </summary>
    /// <param name="encodeJwt">加密后的Jwt令牌</param>
    /// <param name="options">Jwt选项配置</param>
    /// <param name="validatePayload">校验负载</param>
    public Boolean Validate(String encodeJwt, JwtOptions options, Func<IDictionary<String, Object>, JwtOptions, Boolean> validatePayload)
    {
        var httpContext = DHWeb.HttpContext;
        if (httpContext == null) return false;

        // 尝试从缓存中获取已解码的Token信息
        var cacheKey = CachedTokenInfo.GetCacheKey(encodeJwt);
        if (httpContext.Items.TryGetValue(cacheKey, out var cachedObj) && cachedObj is CachedTokenInfo cachedInfo && cachedInfo.IsCacheValid)
        {
            // 使用缓存的解码信息，避免重复解码
            if (cachedInfo.Header != null && cachedInfo.Payload != null)
            {
                httpContext.Items["jwt-header"] = cachedInfo.Header;
                httpContext.Items["jwt-payload"] = cachedInfo.Payload;

                // 如果已经验证过签名，直接进行自定义验证
                if (cachedInfo.IsSignatureValid)
                {
                    return validatePayload(cachedInfo.Payload, options);
                }
            }
        }

        // 如果没有缓存信息，进行完整验证
        var jwtArray = encodeJwt.Split('.');
        if (jwtArray.Length < 3)
            return false;

        // 验证签名（如果配置了Secret）
        if (!options.Secret.IsNullOrWhiteSpace())
        {
            if (!JwtBuilderFactory.ValidateSignature(encodeJwt, options.Secret))
                return false;
        }

        // 在签名验证通过后再解析Header和Payload，避免无效Token的解析开销
        var header = jwtArray[0].ToBase64().ToStr().DecodeJson();
        var payload = jwtArray[1].ToBase64().ToStr().DecodeJson();

        httpContext.Items["jwt-header"] = header;
        httpContext.Items["jwt-payload"] = payload;

        return validatePayload(payload, options);
    }
}
