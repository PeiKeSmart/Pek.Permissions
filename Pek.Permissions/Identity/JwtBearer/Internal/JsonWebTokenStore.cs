using NewLife.Caching;

using Pek.Security;

namespace Pek.Permissions.Identity.JwtBearer.Internal;

/// <summary>
/// Jwt令牌存储器
/// </summary>
internal sealed class JsonWebTokenStore : IJsonWebTokenStore
{
    /// <summary>
    /// 缓存
    /// </summary>
    private readonly ICache _cache;

    /// <summary>
    /// 初始化一个<see cref="JsonWebTokenStore"/>类型的实例
    /// </summary>
    /// <param name="cacheProvider"></param>
    public JsonWebTokenStore(ICacheProvider cacheProvider)
    {
        _cache = cacheProvider.Cache;
        //if (RedisSetting.Current.RedisEnabled)
        //{
        //    _cache = Singleton<FullRedis>.Instance;
        //    if (_cache == null)
        //    {
        //        XTrace.WriteLine($"[JsonWebTokenStore.JsonWebTokenStore]Redis缓存对象为空，请检查是否注入FullRedis");
        //    }
        //}
        //else
        //{
        //    _cache = cache;
        //}
    }

    /// <summary>
    /// 获取刷新令牌
    /// </summary>
    /// <param name="token">刷新令牌</param>
    public RefreshToken GetRefreshToken(String token) =>
        _cache.Get<RefreshToken>(GetRefreshTokenKey(token));

    /// <summary>
    /// 保存刷新令牌
    /// </summary>
    /// <param name="token">刷新令牌</param>
    public void SaveRefreshToken(RefreshToken token) => _cache.Set(GetRefreshTokenKey(token.Value), token, token.EndUtcTime.Subtract(DateTime.UtcNow));

    /// <summary>
    /// 移除刷新令牌
    /// </summary>
    /// <param name="token">刷新令牌</param>
    public void RemoveRefreshToken(String token)
    {
        if (!_cache.ContainsKey(GetRefreshTokenKey(token)))
            return;
        _cache.Remove(GetRefreshTokenKey(token));
        if (!_cache.ContainsKey(GetBindRefreshTokenKey(token)))
            return;
        var accessToken = _cache.Get<JsonWebToken>(GetBindRefreshTokenKey(token));
        _cache.Remove(GetBindRefreshTokenKey(token));
        RemoveToken(accessToken.AccessToken);
    }

    /// <summary>
    /// 移除刷新令牌
    /// </summary>
    /// <param name="token">刷新令牌</param>
    /// <param name="expire">延时时间。秒</param>
    public void RemoveRefreshToken(String token, Int32 expire)
    {
        var key = GetRefreshTokenKey(token);
        var key1 = GetBindRefreshTokenKey(token);

        if (!_cache.ContainsKey(key))
            return;
        _cache.SetExpire(key, TimeSpan.FromSeconds(expire));

        if (!_cache.ContainsKey(key1))
            return;
        _cache.SetExpire(key1, TimeSpan.FromSeconds(expire));

        var accessToken = _cache.Get<JsonWebToken>(key1);
        RemoveToken(accessToken.AccessToken, expire);
    }

    /// <summary>
    /// 获取访问令牌
    /// </summary>
    /// <param name="token">访问令牌</param>
    public JsonWebToken GetToken(String token) => _cache.Get<JsonWebToken>(GetTokenKey(token));

    /// <summary>
    /// 移除访问令牌
    /// </summary>
    /// <param name="token">访问令牌</param>
    public void RemoveToken(String token)
    {
        if (!_cache.ContainsKey(GetTokenKey(token)))
            return;
            
        // 获取token信息以找到userId
        var jsonWebToken = _cache.Get<JsonWebToken>(GetTokenKey(token));
        if (jsonWebToken != null)
        {
            var userId = jsonWebToken.UId.ToString();
            // 清理用户Token关联
            RemoveUserToken(userId, token);
        }
        
        _cache.Remove(GetTokenKey(token));
    }

    /// <summary>
    /// 移除访问令牌
    /// </summary>
    /// <param name="token">访问令牌</param>
    /// <param name="expire">延时时间。秒</param>
    public void RemoveToken(String token, Int32 expire)
    {
        var key = GetTokenKey(token);

        if (!_cache.ContainsKey(key))
            return;

        // 获取token信息以找到userId（延时移除时也需要清理用户关联）
        var jsonWebToken = _cache.Get<JsonWebToken>(key);
        if (jsonWebToken != null)
        {
            var userId = jsonWebToken.UId.ToString();
            // 立即清理用户Token关联（不延时）
            RemoveUserToken(userId, token);
        }

        _cache.SetExpire(key, TimeSpan.FromSeconds(expire));
    }

    /// <summary>
    /// 保存访问令牌
    /// </summary>
    /// <param name="token">令牌</param>
    /// <param name="expires">过期时间</param>
    public void SaveToken(JsonWebToken token, DateTime expires)
    {
        _cache.Set(GetTokenKey(token.AccessToken), token, expires.Subtract(DateTime.UtcNow));
        _cache.Set(GetBindRefreshTokenKey(token.RefreshToken), token, expires.Subtract(DateTime.UtcNow));
    }

    /// <summary>
    /// 是否存在访问令牌
    /// </summary>
    /// <param name="token">访问令牌</param>
    public Boolean ExistsToken(String token) => _cache.ContainsKey(GetTokenKey(token));

    /// <summary>
    /// 绑定用户设备令牌
    /// </summary>
    /// <param name="userId">用户标识</param>
    /// <param name="clientType">客户端类型</param>
    /// <param name="info">设备信息</param>
    /// <param name="expires">过期时间</param>
    public void BindUserDeviceToken(String userId, String clientType, DeviceTokenBindInfo info,
        DateTime expires) => _cache.Set(GetBindUserDeviceTokenKey(userId, clientType), info,
        expires.Subtract(DateTime.UtcNow));

    /// <summary>
    /// 获取用户设备令牌
    /// </summary>
    /// <param name="userId">用户标识</param>
    /// <param name="clientType">客户端类型</param>
    public DeviceTokenBindInfo GetUserDeviceToken(String userId, String clientType) =>
        _cache.Get<DeviceTokenBindInfo>(GetBindUserDeviceTokenKey(userId, clientType));

    /// <summary>
    /// 获取刷新令牌缓存键
    /// </summary>
    /// <param name="token">刷新令牌</param>
    private static String GetRefreshTokenKey(String token) => $"jwt:token:refresh:{token}";

    /// <summary>
    /// 获取访问令牌缓存键
    /// </summary>
    /// <param name="token">访问令牌</param>
    private static String GetTokenKey(String token) => $"jwt:token:access:{token}";

    /// <summary>
    /// 获取绑定刷新令牌缓存键
    /// </summary>
    /// <param name="token">刷新令牌</param>
    private static String GetBindRefreshTokenKey(String token) => $"jwt:token:bind:{token}";

    /// <summary>
    /// 获取绑定用户设备令牌缓存键
    /// </summary>
    /// <param name="userId">用户标识</param>
    /// <param name="clientType">客户端类型</param>
    private static String GetBindUserDeviceTokenKey(String userId, String clientType) =>
        $"jwt:token:bind_user:{userId}:{clientType}";

    #region 用户Token管理

    /// <summary>
    /// 添加用户Token关联
    /// </summary>
    /// <param name="userId">用户标识</param>
    /// <param name="accessToken">访问令牌</param>
    /// <param name="expires">过期时间</param>
    public void AddUserToken(String userId, String accessToken, DateTime expires)
    {
        var userTokensKey = GetUserTokensKey(userId);
        
        // 获取现有的token列表
        var existingTokens = _cache.Get<HashSet<String>>(userTokensKey) ?? [];
        existingTokens.Add(accessToken);
        
        // 保存更新后的token列表
        _cache.Set(userTokensKey, existingTokens, expires.Add(TimeSpan.FromHours(1)).Subtract(DateTime.UtcNow));
    }

    /// <summary>
    /// 移除用户Token关联
    /// </summary>
    /// <param name="userId">用户标识</param>
    /// <param name="accessToken">访问令牌</param>
    public void RemoveUserToken(String userId, String accessToken)
    {
        var userTokensKey = GetUserTokensKey(userId);
        var existingTokens = _cache.Get<HashSet<String>>(userTokensKey);
        
        if (existingTokens != null)
        {
            existingTokens.Remove(accessToken);
            
            if (existingTokens.Count > 0)
            {
                _cache.Set(userTokensKey, existingTokens);
            }
            else
            {
                _cache.Remove(userTokensKey);
            }
        }
    }

    /// <summary>
    /// 获取用户的所有AccessToken
    /// </summary>
    /// <param name="userId">用户标识</param>
    public IEnumerable<String> GetUserAccessTokens(String userId)
    {
        var userTokensKey = GetUserTokensKey(userId);
        var tokens = _cache.Get<HashSet<String>>(userTokensKey) ?? new HashSet<String>();
        
        // 过滤掉已过期的token
        var validTokens = new HashSet<String>();
        var hasExpiredTokens = false;
        
        foreach (var token in tokens)
        {
            if (_cache.ContainsKey(GetTokenKey(token)))
            {
                validTokens.Add(token);
            }
            else
            {
                hasExpiredTokens = true;
            }
        }
        
        // 如果有过期token，更新缓存
        if (hasExpiredTokens && validTokens.Count != tokens.Count)
        {
            if (validTokens.Count > 0)
            {
                _cache.Set(userTokensKey, validTokens);
            }
            else
            {
                _cache.Remove(userTokensKey);
            }
        }
        
        return validTokens;
    }

    /// <summary>
    /// 移除用户的所有Token
    /// </summary>
    /// <param name="userId">用户标识</param>
    public void RemoveAllUserTokens(String userId)
    {
        var tokens = GetUserAccessTokens(userId);
        
        foreach (var accessToken in tokens)
        {
            // 获取对应的JsonWebToken对象
            var jsonWebToken = GetToken(accessToken);
            if (jsonWebToken != null)
            {
                // 删除AccessToken
                RemoveToken(accessToken);
                
                // 删除对应的RefreshToken
                if (!String.IsNullOrEmpty(jsonWebToken.RefreshToken))
                {
                    RemoveRefreshToken(jsonWebToken.RefreshToken);
                }
            }
        }
        
        // 清空用户Token列表
        _cache.Remove(GetUserTokensKey(userId));
    }

    /// <summary>
    /// 获取用户Token列表缓存键
    /// </summary>
    /// <param name="userId">用户标识</param>
    private static String GetUserTokensKey(String userId) => $"jwt:user:tokens:{userId}";

    #endregion
}
