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
    /// 是否使用Redis缓存
    /// </summary>
    private readonly Boolean _isRedis;

    /// <summary>
    /// 用户Token集合操作信号量（针对MemoryCache下的HashSet并发安全）
    /// </summary>
    private readonly Dictionary<String, SemaphoreSlim> _userTokenSemaphores = new();
    private readonly SemaphoreSlim _semaphoreDict = new(1, 1);

    /// <summary>
    /// 初始化一个<see cref="JsonWebTokenStore"/>类型的实例
    /// </summary>
    /// <param name="cacheProvider"></param>
    public JsonWebTokenStore(ICacheProvider cacheProvider)
    {
        _cache = cacheProvider.Cache;

        if (cacheProvider.Cache != cacheProvider.InnerCache && cacheProvider.Cache is not MemoryCache)
            _isRedis = true;

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
        RemoveTokenInternal(token, true);
    }

    /// <summary>
    /// 内部移除访问令牌方法
    /// </summary>
    /// <param name="token">访问令牌</param>
    /// <param name="removeUserAssociation">是否移除用户关联</param>
    private void RemoveTokenInternal(String token, Boolean removeUserAssociation)
    {
        if (!_cache.ContainsKey(GetTokenKey(token)))
            return;

        // 获取token信息以找到userId
        var jsonWebToken = _cache.Get<JsonWebToken>(GetTokenKey(token));
        if (jsonWebToken != null && removeUserAssociation)
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
        
        // 添加用户Token关联
        if (token.UId > 0)
        {
            AddUserToken(token.UId.ToString(), token.AccessToken, expires);
        }
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
    /// 获取用户级别的信号量，用于保证Token集合操作的并发安全
    /// </summary>
    /// <param name="userId">用户ID</param>
    /// <returns>用户专用的信号量</returns>
    private SemaphoreSlim GetUserSemaphore(String userId)
    {
        _semaphoreDict.Wait();
        try
        {
            if (!_userTokenSemaphores.TryGetValue(userId, out var semaphore))
            {
                semaphore = new SemaphoreSlim(1, 1);
                _userTokenSemaphores[userId] = semaphore;
            }
            return semaphore;
        }
        finally
        {
            _semaphoreDict.Release();
        }
    }

    /// <summary>
    /// 清理未使用的用户信号量（可选的内存优化）
    /// </summary>
    /// <param name="userId">用户ID</param>
    private void CleanupUserSemaphore(String userId)
    {
        _semaphoreDict.Wait();
        try
        {
            if (_userTokenSemaphores.TryGetValue(userId, out var semaphore))
            {
                // 检查是否有等待的线程，如果没有则可以安全移除
                if (semaphore.CurrentCount == 1)
                {
                    _userTokenSemaphores.Remove(userId);
                    semaphore.Dispose();
                }
            }
        }
        finally
        {
            _semaphoreDict.Release();
        }
    }

    /// <summary>
    /// 添加用户Token关联
    /// </summary>
    /// <param name="userId">用户标识</param>
    /// <param name="accessToken">访问令牌</param>
    /// <param name="expires">过期时间</param>
    public void AddUserToken(String userId, String accessToken, DateTime expires)
    {
        if (_isRedis)
        {
            AddUserTokenForRedis(userId, accessToken, expires);
        }
        else
        {
            AddUserTokenForMemory(userId, accessToken, expires);
        }
    }

    /// <summary>
    /// 移除用户Token关联
    /// </summary>
    /// <param name="userId">用户标识</param>
    /// <param name="accessToken">访问令牌</param>
    public void RemoveUserToken(String userId, String accessToken)
    {
        if (_isRedis)
        {
            RemoveUserTokenForRedis(userId, accessToken);
        }
        else
        {
            RemoveUserTokenForMemory(userId, accessToken);
        }
    }

    /// <summary>
    /// 获取用户的所有AccessToken
    /// </summary>
    /// <param name="userId">用户标识</param>
    public IEnumerable<String> GetUserAccessTokens(String userId)
    {
        if (_isRedis)
        {
            return GetUserAccessTokensForRedis(userId);
        }
        else
        {
            return GetUserAccessTokensForMemory(userId);
        }
    }

    /// <summary>
    /// 移除用户的所有Token
    /// </summary>
    /// <param name="userId">用户标识</param>
    public void RemoveAllUserTokens(String userId)
    {
        if (_isRedis)
        {
            RemoveAllUserTokensForRedis(userId);
        }
        else
        {
            RemoveAllUserTokensForMemory(userId);
        }
    }

    #region Redis模式实现

    /// <summary>
    /// Redis模式：添加用户Token关联
    /// </summary>
    /// <param name="userId">用户标识</param>
    /// <param name="accessToken">访问令牌</param>
    /// <param name="expires">过期时间</param>
    private void AddUserTokenForRedis(String userId, String accessToken, DateTime expires)
    {
        var userTokensKey = GetUserTokensKey(userId);
        
        // Redis模式下，我们使用Set集合存储用户Token
        // 由于NewLife.Caching的统一接口，我们可以通过Set操作来实现
        var existingTokens = _cache.Get<HashSet<String>>(userTokensKey) ?? new HashSet<String>();
        existingTokens.Add(accessToken);
        
        // 保存更新后的token列表，设置稍长的过期时间
        var expireTime = expires.Add(TimeSpan.FromHours(1)).Subtract(DateTime.UtcNow);
        _cache.Set(userTokensKey, existingTokens, expireTime);
    }

    /// <summary>
    /// Redis模式：移除用户Token关联
    /// </summary>
    /// <param name="userId">用户标识</param>
    /// <param name="accessToken">访问令牌</param>
    private void RemoveUserTokenForRedis(String userId, String accessToken)
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
    /// Redis模式：获取用户的所有AccessToken
    /// </summary>
    /// <param name="userId">用户标识</param>
    /// <returns>Token列表</returns>
    private IEnumerable<String> GetUserAccessTokensForRedis(String userId)
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
        
        return validTokens.ToList();
    }

    /// <summary>
    /// Redis模式：移除用户的所有Token
    /// </summary>
    /// <param name="userId">用户标识</param>
    private void RemoveAllUserTokensForRedis(String userId)
    {
        var tokens = GetUserAccessTokensForRedis(userId);
        
        foreach (var accessToken in tokens)
        {
            // 获取对应的JsonWebToken对象
            var jsonWebToken = GetToken(accessToken);
            if (jsonWebToken != null)
            {
                // 删除AccessToken（不移除用户关联，避免递归）
                RemoveTokenInternal(accessToken, false);
                
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

    #endregion

    #region Memory模式实现

    /// <summary>
    /// Memory模式：添加用户Token关联
    /// </summary>
    /// <param name="userId">用户标识</param>
    /// <param name="accessToken">访问令牌</param>
    /// <param name="expires">过期时间</param>
    private void AddUserTokenForMemory(String userId, String accessToken, DateTime expires)
    {
        var userSemaphore = GetUserSemaphore(userId);
        userSemaphore.Wait();
        try
        {
            var userTokensKey = GetUserTokensKey(userId);
            
            // 获取现有的token列表
            var existingTokens = _cache.Get<HashSet<String>>(userTokensKey) ?? [];
            existingTokens.Add(accessToken);
            
            // 保存更新后的token列表
            _cache.Set(userTokensKey, existingTokens, expires.Add(TimeSpan.FromHours(1)).Subtract(DateTime.UtcNow));
        }
        finally
        {
            userSemaphore.Release();
        }
    }

    /// <summary>
    /// Memory模式：移除用户Token关联
    /// </summary>
    /// <param name="userId">用户标识</param>
    /// <param name="accessToken">访问令牌</param>
    private void RemoveUserTokenForMemory(String userId, String accessToken)
    {
        var userSemaphore = GetUserSemaphore(userId);
        userSemaphore.Wait();
        try
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
                    // 当用户没有Token时，清理信号量（可选的内存优化）
                    CleanupUserSemaphore(userId);
                }
            }
        }
        finally
        {
            userSemaphore.Release();
        }
    }

    /// <summary>
    /// Memory模式：获取用户的所有AccessToken
    /// </summary>
    /// <param name="userId">用户标识</param>
    /// <returns>Token列表</returns>
    private IEnumerable<String> GetUserAccessTokensForMemory(String userId)
    {
        var userSemaphore = GetUserSemaphore(userId);
        userSemaphore.Wait();
        try
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
                    // 当用户没有Token时，清理信号量（可选的内存优化）
                    CleanupUserSemaphore(userId);
                }
            }
            
            return validTokens.ToList(); // 返回副本避免外部修改
        }
        finally
        {
            userSemaphore.Release();
        }
    }

    /// <summary>
    /// Memory模式：移除用户的所有Token
    /// </summary>
    /// <param name="userId">用户标识</param>
    private void RemoveAllUserTokensForMemory(String userId)
    {
        var userSemaphore = GetUserSemaphore(userId);
        userSemaphore.Wait();
        try
        {
            var tokens = GetUserAccessTokensForMemoryInternal(userId); // 内部方法，避免重复加锁
            
            foreach (var accessToken in tokens)
            {
                // 获取对应的JsonWebToken对象
                var jsonWebToken = GetToken(accessToken);
                if (jsonWebToken != null)
                {
                    // 删除AccessToken（不移除用户关联，避免递归）
                    RemoveTokenInternal(accessToken, false);
                    
                    // 删除对应的RefreshToken
                    if (!String.IsNullOrEmpty(jsonWebToken.RefreshToken))
                    {
                        RemoveRefreshToken(jsonWebToken.RefreshToken);
                    }
                }
            }
            
            // 清空用户Token列表
            _cache.Remove(GetUserTokensKey(userId));
            
            // 清理信号量（可选的内存优化）
            CleanupUserSemaphore(userId);
        }
        finally
        {
            userSemaphore.Release();
        }
    }

    /// <summary>
    /// Memory模式：获取用户的所有AccessToken（内部方法，不加锁）
    /// </summary>
    /// <param name="userId">用户标识</param>
    /// <returns>Token列表</returns>
    private IEnumerable<String> GetUserAccessTokensForMemoryInternal(String userId)
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
        
        return validTokens.ToList();
    }

    #endregion

    /// <summary>
    /// 获取用户Token列表缓存键
    /// </summary>
    /// <param name="userId">用户标识</param>
    private static String GetUserTokensKey(String userId) => $"jwt:user:tokens:{userId}";

    #endregion
}
