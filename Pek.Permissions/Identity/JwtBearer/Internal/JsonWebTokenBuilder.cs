using Microsoft.Extensions.Options;

using NewLife;
using NewLife.Web;

using Pek.Exceptions;
using Pek.Helpers;
using Pek.Security;
using Pek.Timing;

namespace Pek.Permissions.Identity.JwtBearer.Internal;

/// <summary>
/// Jwt构建器
/// </summary>
internal sealed class JsonWebTokenBuilder : IJsonWebTokenBuilder
{
    /// <summary>
    /// Jwt令牌存储器
    /// </summary>
    private readonly IJsonWebTokenStore _tokenStore;

    /// <summary>
    /// 令牌Payload存储器
    /// </summary>
    private readonly ITokenPayloadStore _tokenPayloadStore;

    /// <summary>
    /// Jwt选项配置
    /// </summary>
    private readonly JwtOptions _options;

    /// <summary>
    /// 初始化一个<see cref="JsonWebTokenBuilder"/>类型的实例
    /// </summary>
    /// <param name="tokenStore">Jwt令牌存储器</param>
    /// <param name="tokenPayloadStore">令牌Payload存储器</param>
    /// <param name="options">Jwt选项配置</param>
    public JsonWebTokenBuilder(IJsonWebTokenStore tokenStore
        , ITokenPayloadStore tokenPayloadStore
        , IOptions<JwtOptions> options)
    {
        _tokenStore = tokenStore;
        _tokenPayloadStore = tokenPayloadStore;
        _options = options.Value;
    }

    /// <summary>
    /// 创建令牌
    /// </summary>
    /// <param name="payload">负载</param>
    public JsonWebToken Create(IDictionary<String, String> payload) => Create(payload, _options);

    /// <summary>
    /// 创建令牌
    /// </summary>
    /// <param name="payload">负载</param>
    /// <param name="AccessExpireMinutes">访问令牌有效期分钟数</param>
    /// <param name="RefreshExpireMinutes">刷新令牌有效期分钟数</param>
    public JsonWebToken Create(IDictionary<String, String> payload, Double RefreshExpireMinutes, Double AccessExpireMinutes = 0)
    {
        var options = _options.DeepCloneWithJson();

        if (AccessExpireMinutes > 0)
        {
            options.AccessExpireMinutes = AccessExpireMinutes;
        }

        if (RefreshExpireMinutes > 0)
        {
            options.RefreshExpireMinutes = RefreshExpireMinutes;
        }

        return Create(payload, options);
    }

    /// <summary>
    /// 创建令牌
    /// </summary>
    /// <param name="payload">负载</param>
    /// <param name="options">Jwt选项配置</param>
    public JsonWebToken Create(IDictionary<String, String> payload, JwtOptions options)
    {
        if (options.Secret.IsNullOrWhiteSpace())
            throw new ArgumentNullException(nameof(options.Secret),
                $@"{nameof(options.Secret)}为Null或空字符串。请在""appsettings.json""配置""{nameof(JwtOptions)}""节点及其子节点""{nameof(JwtOptions.Secret)}""");
        var clientId = payload.ContainsKey("clientId") ? payload["clientId"] : Guid.NewGuid().ToString();
        var clientType = payload.ContainsKey("clientType") ? payload["clientType"] : "admin";
        var userId = GetUserId(payload);
        if (userId.IsEmpty())
            throw new ArgumentException("不存在用户标识");
        var claims = Helper.ToClaims(payload);

        var ss = options.Secret.Split(':');
        var jwt = new JwtBuilder
        {
            Issuer = options.Issuer,
            Subject = userId,
            Id = userId,

            Algorithm = ss[0],
            Secret = ss[1],
        };

        jwt.Expire = DateTime.Now.AddMinutes(options.RefreshExpireMinutes);
        var refreshToken = jwt.Encode(payload);
        var refreshExpires = jwt.Expire;

        // 生成刷新令牌
        _tokenStore.SaveRefreshToken(new RefreshToken()
        {
            ClientId = clientId,
            EndUtcTime = refreshExpires,
            Value = refreshToken
        });

        jwt.Expire = DateTime.Now.AddMinutes(options.AccessExpireMinutes);
        var token = jwt.Encode(payload);
        var accessExpires = jwt.Expire;

        // 生成访问令牌
        var accessToken = new JsonWebToken()
        {
            AccessToken = token,
            AccessTokenUtcExpires = Conv.CTo<Int64>(accessExpires.ToJsGetTime()),
            RefreshToken = refreshToken,
            RefreshUtcExpires = Conv.CTo<Int64>(refreshExpires.ToJsGetTime())
        };
        _tokenStore.SaveToken(accessToken, accessExpires);

        // 绑定用户设备令牌
        _tokenStore.BindUserDeviceToken(userId, clientType, new DeviceTokenBindInfo()
        {
            UserId = userId,
            DeviceId = clientId,
            DeviceType = clientType,
            Token = accessToken,
        }, refreshExpires);
        // 存储payload
        _tokenPayloadStore.Save(refreshToken, payload, refreshExpires);
        _tokenPayloadStore.Save(token, payload, accessExpires);
        return accessToken;
    }

    /// <summary>
    /// 获取用户标识
    /// </summary>
    /// <param name="payload">负载列表</param>
    private string GetUserId(IDictionary<String, String> payload)
    {
        var userId = payload.GetOrDefault(System.Security.Claims.ClaimTypes.Sid, String.Empty);

        return userId;
    }

    /// <summary>
    /// 刷新令牌
    /// </summary>
    /// <param name="refreshToken">刷新令牌</param>
    public JsonWebToken Refresh(String refreshToken) => Refresh(refreshToken, _options);

    /// <summary>
    /// 刷新令牌
    /// </summary>
    /// <param name="refreshToken">刷新令牌</param>
    /// <param name="RefreshExpireMinutes">刷新令牌有效期分钟数</param>
    public JsonWebToken Refresh(String refreshToken, Double RefreshExpireMinutes)
    {
        var options = _options.DeepCloneWithJson();

        if (RefreshExpireMinutes > 0)
        {
            options.RefreshExpireMinutes = RefreshExpireMinutes;
        }

        return Refresh(refreshToken, _options);
    }

    /// <summary>
    /// 刷新令牌
    /// </summary>
    /// <param name="refreshToken">刷新令牌</param>
    /// <param name="options"></param>
    public JsonWebToken Refresh(string refreshToken, JwtOptions options)
    {
        if (refreshToken.IsNullOrWhiteSpace())
            throw new ArgumentNullException(nameof(refreshToken));

        var tokenModel = _tokenStore.GetRefreshToken(refreshToken);
        if (tokenModel == null || tokenModel.Value != refreshToken || tokenModel.EndUtcTime <= DateTime.UtcNow)
        {
            if (tokenModel != null && tokenModel.EndUtcTime <= DateTime.UtcNow)
            {
                _tokenStore.RemoveRefreshToken(refreshToken);
                _tokenPayloadStore.Remove(refreshToken);
            }

            throw new Warning("刷新令牌不存在或已过期");
        }
        
        var payload = _tokenPayloadStore.Get(refreshToken);
        var result = Create(payload, options);
        if (result != null)
        {
            _tokenStore.RemoveRefreshToken(refreshToken);
            _tokenPayloadStore.Remove(refreshToken);
        }
        return result;
    }

    /// <summary>
    /// 刷新令牌，延时清理数据
    /// </summary>
    /// <param name="refreshToken">刷新令牌</param>
    /// <param name="expire">延时时间。秒</param>
    public JsonWebToken Refresh(String refreshToken, Int32 expire) => Refresh(refreshToken, expire, _options);

    /// <summary>
    /// 刷新令牌，延时清理数据
    /// </summary>
    /// <param name="refreshToken">刷新令牌</param>
    /// <param name="expire">延时时间。秒</param>
    /// <param name="RefreshExpireMinutes">刷新令牌有效期分钟数</param>
    public JsonWebToken Refresh(String refreshToken, Int32 expire, Double RefreshExpireMinutes)
    {
        var options = _options.DeepCloneWithJson();

        if (RefreshExpireMinutes > 0)
        {
            options.RefreshExpireMinutes = RefreshExpireMinutes;
        }

        return Refresh(refreshToken, expire, _options);
    }

    /// <summary>
    /// 刷新令牌，延时清理数据
    /// </summary>
    /// <param name="refreshToken">刷新令牌</param>
    /// <param name="expire">延时时间。秒</param>
    /// <param name="options"></param>
    public JsonWebToken Refresh(String refreshToken, Int32 expire, JwtOptions options)
    {
        if (String.IsNullOrWhiteSpace(refreshToken))
            throw new ArgumentNullException(nameof(refreshToken));

        var tokenModel = _tokenStore.GetRefreshToken(refreshToken);
        if (tokenModel == null || tokenModel.Value != refreshToken || tokenModel.EndUtcTime <= DateTime.UtcNow)
        {
            if (tokenModel != null && tokenModel.EndUtcTime <= DateTime.UtcNow)
            {
                _tokenStore.RemoveRefreshToken(refreshToken);
                _tokenPayloadStore.Remove(refreshToken);
            }

            throw new Warning("刷新令牌不存在或已过期");
        }

        var payload = _tokenPayloadStore.Get(refreshToken);
        var result = Create(payload, _options);
        if (result != null)
        {
            _tokenStore.RemoveRefreshToken(refreshToken, expire);
            _tokenPayloadStore.Remove(refreshToken, expire);
        }
        return result;
    }
}
