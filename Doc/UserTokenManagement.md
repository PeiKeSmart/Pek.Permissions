# 用户Token管理功能使用说明

## 概述

本次更新为JWT权限系统添加了基于UserId的Token管理功能，支持：
- 查询用户的所有活跃Token
- 强制用户下线（撤销所有Token）
- 撤销用户的指定Token
- 根据Token查找用户

## 新增功能

### 1. 自动Token关联
现在创建Token时会自动建立用户关联，删除Token时也会自动清理关联关系。

### 2. 用户Token管理API

```csharp
// 注入用户Token管理服务
public class UserController : ControllerBase
{
    private readonly IUserTokenService _userTokenService;
    
    public UserController(IUserTokenService userTokenService)
    {
        _userTokenService = userTokenService;
    }
    
    // 获取用户的所有活跃Token
    [HttpGet("tokens/{userId}")]
    public IActionResult GetUserTokens(string userId)
    {
        var tokens = _userTokenService.GetUserTokens(userId);
        return Ok(tokens.Select(t => new
        {
            AccessToken = t.AccessTokenHash, // 使用哈希值保护隐私
            ClientType = t.ClientType,
            DeviceId = t.DeviceId,
            ExpiresAt = t.AccessTokenExpires,
            IsExpired = t.IsExpired
        }));
    }
    
    // 强制用户下线
    [HttpPost("logout/{userId}")]
    public IActionResult ForceUserOffline(string userId)
    {
        _userTokenService.ForceUserOffline(userId);
        return Ok(new { message = $"用户 {userId} 已强制下线" });
    }
    
    // 撤销指定Token
    [HttpDelete("token")]
    public IActionResult RevokeToken([FromBody] RevokeTokenRequest request)
    {
        _userTokenService.RevokeUserToken(request.UserId, request.AccessToken);
        return Ok(new { message = "Token已撤销" });
    }
    
    // 获取用户Token数量
    [HttpGet("token-count/{userId}")]
    public IActionResult GetUserTokenCount(string userId)
    {
        var count = _userTokenService.GetUserTokenCount(userId);
        return Ok(new { userId, tokenCount = count });
    }
}

public class RevokeTokenRequest
{
    public string UserId { get; set; }
    public string AccessToken { get; set; }
}
```

### 3. 管理场景示例

```csharp
public class AdminService
{
    private readonly IUserTokenService _userTokenService;
    
    // 查看在线用户的Token情况
    public async Task<List<UserSessionInfo>> GetOnlineUsersAsync(List<string> userIds)
    {
        var result = new List<UserSessionInfo>();
        
        foreach (var userId in userIds)
        {
            var tokens = _userTokenService.GetUserTokens(userId);
            if (tokens.Any())
            {
                result.Add(new UserSessionInfo
                {
                    UserId = userId,
                    TokenCount = tokens.Count(),
                    LastActiveTime = tokens.Max(t => t.AccessTokenExpires),
                    Sessions = tokens.Select(t => new SessionInfo
                    {
                        TokenHash = t.AccessTokenHash,
                        ClientType = t.ClientType,
                        ExpiresAt = t.AccessTokenExpires
                    }).ToList()
                });
            }
        }
        
        return result;
    }
    
    // 安全策略：限制用户并发登录数
    public bool CheckConcurrentLoginLimit(string userId, int maxTokens = 3)
    {
        var tokenCount = _userTokenService.GetUserTokenCount(userId);
        return tokenCount < maxTokens;
    }
    
    // 异常检测：清理异常Token
    public void CleanupSuspiciousTokens(string userId)
    {
        var tokens = _userTokenService.GetUserTokens(userId);
        
        // 示例：清理超过5个的多余Token（保留最新的5个）
        var sortedTokens = tokens.OrderByDescending(t => t.AccessTokenExpires).ToList();
        var tokensToRemove = sortedTokens.Skip(5);
        
        foreach (var token in tokensToRemove)
        {
            _userTokenService.RevokeUserToken(userId, token.AccessToken);
        }
    }
}

public class UserSessionInfo
{
    public string UserId { get; set; }
    public int TokenCount { get; set; }
    public DateTime LastActiveTime { get; set; }
    public List<SessionInfo> Sessions { get; set; }
}

public class SessionInfo
{
    public string TokenHash { get; set; }
    public string ClientType { get; set; }
    public DateTime ExpiresAt { get; set; }
}
```

## 缓存结构

新增的缓存键：
```
jwt:user:tokens:{userId}    # 用户Token列表 (HashSet<String>)
```

现有缓存键保持不变：
```
jwt:token:access:{token}    # AccessToken信息
jwt:token:refresh:{token}   # RefreshToken信息
jwt:token:bind:{token}      # RefreshToken绑定
jwt:token:bind_user:{userId}:{clientType}  # 用户设备绑定
```

## 兼容性

- ✅ 完全向后兼容，现有代码无需修改
- ✅ 现有Token操作逻辑保持不变
- ✅ RefreshToken处理机制完全保留
- ✅ 渐进式实施，可选择性使用新功能

## 并发安全实现

### MemoryCache 环境下的并发安全

由于 MemoryCache 环境下 `HashSet<String>` 不是线程安全的，我们采用以下策略保证并发安全：

1. **用户级别信号量**：为每个用户维护独立的 `SemaphoreSlim`，避免不同用户间的锁竞争
2. **轻量级锁设计**：使用 `SemaphoreSlim` 而非 `lock` 语句，内存占用更小，性能更好
3. **锁粒度优化**：锁定范围仅限于单个用户的 Token 集合操作，最小化锁持有时间
4. **内存优化**：当用户无Token时自动清理对应的信号量，避免内存泄漏

```csharp
// 用户级别信号量管理
private readonly Dictionary<String, SemaphoreSlim> _userTokenSemaphores = new();
private readonly SemaphoreSlim _semaphoreDict = new(1, 1);

// 获取用户专用信号量
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

// 使用示例：带锁的Token操作
public void AddUserToken(String userId, String accessToken, DateTime expires)
{
    var userSemaphore = GetUserSemaphore(userId);
    userSemaphore.Wait();
    try
    {
        var userTokensKey = GetUserTokensKey(userId);
        var existingTokens = _cache.Get<HashSet<String>>(userTokensKey) ?? [];
        existingTokens.Add(accessToken);
        _cache.Set(userTokensKey, existingTokens, expires.Add(TimeSpan.FromHours(1)).Subtract(DateTime.UtcNow));
    }
    finally
    {
        userSemaphore.Release();
    }
}
```

### Redis 环境下的原生安全

Redis 环境下可直接使用原生的 Set 操作（SADD、SREM、SMEMBERS），天然支持并发安全：

- `SADD jwt:user:tokens:{userId} {accessToken}` - 添加 Token
- `SREM jwt:user:tokens:{userId} {accessToken}` - 移除 Token  
- `SMEMBERS jwt:user:tokens:{userId}` - 获取所有 Token
- `DEL jwt:user:tokens:{userId}` - 清空用户 Token

### 并发控制策略对比

| 方案 | 优势 | 劣势 | 适用场景 |
|------|------|------|----------|
| Dictionary + lock | 实现简单 | 重量级，内存占用大 | 低并发场景 |
| SemaphoreSlim | 轻量级，支持异步 | 需要手动内存管理 | **推荐方案** |
| Redis 原生命令 | 天然线程安全，高性能 | 依赖Redis | Redis环境 |
| 分段锁 | 更高并发度 | 实现复杂 | 极高并发场景 |

## 性能考虑

- 用户Token列表使用 `HashSet<String>` 存储，查询效率 O(1)
- 自动清理过期Token，避免内存泄漏
- 延时删除机制保持不变
- 信号量级别的锁控制，最小化锁竞争

## 安全特性

- 日志中使用Token哈希值，避免敏感信息泄露
- 支持强制下线和精确Token撤销
- 可扩展并发登录限制和异常检测功能
- 并发安全的Token集合管理，避免竞态条件
