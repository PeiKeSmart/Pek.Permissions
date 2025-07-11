# DH.Permissions - JWT权限类库

DH框架的JWT权限类库，提供完整的JWT身份认证和授权解决方案，支持用户Token管理、并发登录控制、强制下线等高级功能。

## 🚀 主要特性

### 核心功能
- ✅ **JWT Token生成与验证** - 支持HS256/HS384/HS512等多种算法
- ✅ **RefreshToken机制** - 自动刷新过期Token，提升用户体验
- ✅ **用户Token管理** - 基于UserId的Token关联管理
- ✅ **并发登录控制** - 支持限制用户同时登录设备数量
- ✅ **强制下线功能** - 管理员可强制用户下线
- ✅ **Token撤销机制** - 精确撤销指定Token
- ✅ **缓存支持** - 支持Redis和Memory两种缓存模式
- ✅ **并发安全** - 完整的线程安全保护机制

### 高级特性
- 🔐 **自定义授权策略** - 灵活的权限控制
- 🛡️ **中间件支持** - 客户端授权中间件
- 📊 **Token统计** - 用户在线状态和Token统计
- 🔍 **Token查找** - 根据Token反查用户信息
- ⚡ **高性能** - 优化的缓存策略和并发控制
- 🔒 **安全特性** - Token哈希保护，避免敏感信息泄露

## 📦 安装

```bash
# NuGet包管理器
Install-Package Pek.Permissions

# .NET CLI
dotnet add package Pek.Permissions
```

## ⚙️ 快速开始

### 1. 服务注册

```csharp
using Pek.Permissions.Extensions;
using Pek.Security;

// Program.cs 或 Startup.cs
builder.Services.AddJwt(options =>
{
    options.Secret = "your-secret-key-here";  // JWT密钥
    options.Issuer = "your-app-name";         // 发行者
    options.Audience = "your-audience";       // 接收者
    options.Expire = 7200;                    // AccessToken过期时间(秒)
    options.RefreshExpire = 604800;           // RefreshToken过期时间(秒)
    options.IsRedis = true;                   // 是否使用Redis缓存
    options.RedisConnectionString = "localhost:6379"; // Redis连接字符串
});

// 添加认证和授权
builder.Services.AddAuthentication()
    .AddPekJwtBearer(); // 使用自定义JWT Bearer认证

builder.Services.AddAuthorization();
```

### 2. 中间件配置

```csharp
// 配置请求管道
app.UseAuthentication();
app.UseAuthorization();

// 可选：使用JWT客户授权中间件
app.UseJwtCustomerAuthorize(options =>
{
    // 设置匿名访问路径
    options.SetAnonymousPaths(new[] { "/api/auth/login", "/api/auth/register" });
    
    // 设置自定义验证逻辑
    options.SetValidateFunc((payload, jwtOptions) =>
    {
        // 自定义验证逻辑
        return payload.ContainsKey("userId");
    });
});
```

### 3. 控制器使用

```csharp
using Pek.Permissions;
using Pek.Permissions.Identity.JwtBearer;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IJsonWebTokenBuilder _tokenBuilder;
    private readonly IUserTokenService _userTokenService;
    
    public AuthController(
        IJsonWebTokenBuilder tokenBuilder,
        IUserTokenService userTokenService)
    {
        _tokenBuilder = tokenBuilder;
        _userTokenService = userTokenService;
    }
    
    /// <summary>
    /// 用户登录
    /// </summary>
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        // 验证用户凭据（省略具体实现）
        var userId = "123";
        var userName = "admin";
        
        // 创建Token负载
        var payload = new Dictionary<string, object>
        {
            ["userId"] = userId,
            ["userName"] = userName,
            ["role"] = "admin"
        };
        
        // 生成Token
        var tokenResult = _tokenBuilder.Create(payload);
        
        return Ok(new
        {
            accessToken = tokenResult.AccessToken,
            refreshToken = tokenResult.RefreshToken,
            tokenType = "Bearer",
            expiresIn = tokenResult.ExpireIn
        });
    }
    
    /// <summary>
    /// 刷新Token
    /// </summary>
    [HttpPost("refresh")]
    public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
    {
        try
        {
            // 刷新Token（延时10秒删除旧Token）
            var newToken = _tokenBuilder.Refresh(request.RefreshToken, 10);
            
            return Ok(new
            {
                accessToken = newToken.AccessToken,
                refreshToken = newToken.RefreshToken,
                tokenType = "Bearer",
                expiresIn = newToken.ExpireIn
            });
        }
        catch (Exception ex)
        {
            return BadRequest(new { message = "刷新Token失败", error = ex.Message });
        }
    }
}

/// <summary>
/// 受保护的API控制器
/// </summary>
[ApiController]
[Route("api/[controller]")]
[JwtAuthorize] // 使用JWT授权
public class UserController : ControllerBase
{
    [HttpGet("profile")]
    public IActionResult GetProfile()
    {
        var userId = User.FindFirst("userId")?.Value;
        return Ok(new { userId, message = "这是受保护的用户信息" });
    }
    
    /// <summary>
    /// 多来源JWT授权示例
    /// </summary>
    [HttpGet("admin")]
    [JwtAuthorize(From = "admin")] // 指定来源
    public IActionResult AdminOnly()
    {
        return Ok(new { message = "管理员专用接口" });
    }
}
```

## 🔧 用户Token管理

### Token管理服务

```csharp
[ApiController]
[Route("api/[controller]")]
public class TokenManagementController : ControllerBase
{
    private readonly IUserTokenService _userTokenService;
    
    public TokenManagementController(IUserTokenService userTokenService)
    {
        _userTokenService = userTokenService;
    }
    
    /// <summary>
    /// 获取用户的所有Token
    /// </summary>
    [HttpGet("{userId}/tokens")]
    public IActionResult GetUserTokens(string userId)
    {
        var tokens = _userTokenService.GetUserTokens(userId);
        return Ok(tokens.Select(t => new
        {
            tokenHash = t.AccessTokenHash,
            clientType = t.ClientType,
            deviceId = t.DeviceId,
            accessTokenExpires = t.AccessTokenExpires,
            refreshTokenExpires = t.RefreshTokenExpires,
            isExpired = t.IsExpired
        }));
    }
    
    /// <summary>
    /// 强制用户下线
    /// </summary>
    [HttpPost("{userId}/logout")]
    public IActionResult ForceLogout(string userId)
    {
        var tokenCount = _userTokenService.GetUserTokenCount(userId);
        _userTokenService.ForceUserOffline(userId);
        
        return Ok(new
        {
            message = $"用户 {userId} 已强制下线",
            revokedTokenCount = tokenCount
        });
    }
    
    /// <summary>
    /// 撤销指定Token
    /// </summary>
    [HttpDelete("{userId}/tokens")]
    public IActionResult RevokeToken(string userId, [FromBody] RevokeTokenRequest request)
    {
        _userTokenService.RevokeUserToken(userId, request.AccessToken);
        return Ok(new { message = "Token已撤销" });
    }
    
    /// <summary>
    /// 根据Token查找用户
    /// </summary>
    [HttpPost("find-user")]
    public IActionResult FindUserByToken([FromBody] FindUserRequest request)
    {
        var userId = _userTokenService.GetUserIdByToken(request.AccessToken);
        
        if (string.IsNullOrEmpty(userId))
        {
            return NotFound(new { message = "Token不存在或已过期" });
        }
        
        return Ok(new { userId });
    }
    
    /// <summary>
    /// 获取Token统计信息
    /// </summary>
    [HttpGet("statistics")]
    public IActionResult GetTokenStatistics([FromQuery] string[] userIds)
    {
        var statistics = userIds.Select(userId => new
        {
            userId,
            tokenCount = _userTokenService.GetUserTokenCount(userId),
            hasActiveTokens = _userTokenService.GetUserTokenCount(userId) > 0
        });
        
        return Ok(new
        {
            totalUsers = userIds.Length,
            onlineUsers = statistics.Count(s => s.hasActiveTokens),
            statistics
        });
    }
}
```

### 并发登录控制

```csharp
public class LoginService
{
    private readonly IUserTokenService _userTokenService;
    private readonly IJsonWebTokenBuilder _tokenBuilder;
    
    /// <summary>
    /// 带并发控制的登录
    /// </summary>
    public async Task<LoginResult> LoginWithConcurrencyControl(
        string userId, 
        Dictionary<string, object> payload,
        int maxConcurrentLogins = 3)
    {
        // 检查当前Token数量
        var currentTokenCount = _userTokenService.GetUserTokenCount(userId);
        
        if (currentTokenCount >= maxConcurrentLogins)
        {
            // 可选择：拒绝登录或踢掉最旧的Token
            var tokens = _userTokenService.GetUserTokens(userId)
                .OrderBy(t => t.AccessTokenExpires)
                .Take(currentTokenCount - maxConcurrentLogins + 1);
                
            foreach (var token in tokens)
            {
                _userTokenService.RevokeUserToken(userId, token.AccessToken);
            }
        }
        
        // 创建新Token
        var tokenResult = _tokenBuilder.Create(payload);
        
        return new LoginResult
        {
            AccessToken = tokenResult.AccessToken,
            RefreshToken = tokenResult.RefreshToken,
            ExpiresIn = tokenResult.ExpireIn
        };
    }
}
```

## 🔐 高级配置

### 自定义授权策略

```csharp
// 注册自定义授权策略
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.Requirements.Add(new JsonWebTokenAuthorizationRequirement()
            .SetValidateFunc((payload, jwtOptions) =>
            {
                return payload.TryGetValue("role", out var role) && 
                       role.ToString() == "admin";
            }));
    });
    
    options.AddPolicy("VipUser", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.Requirements.Add(new JsonWebTokenAuthorizationRequirement()
            .SetValidateFunc((payload, jwtOptions) =>
            {
                return payload.TryGetValue("userLevel", out var level) && 
                       int.Parse(level.ToString()) >= 5;
            }));
    });
});

// 在控制器中使用
[Authorize(Policy = "AdminOnly")]
public IActionResult AdminFunction() { /* ... */ }

[Authorize(Policy = "VipUser")]
public IActionResult VipFunction() { /* ... */ }
```

### Redis配置

```csharp
// appsettings.json
{
  "JwtOptions": {
    "Secret": "your-256-bit-secret-key-here",
    "Issuer": "YourAppName",
    "Audience": "YourAudience",
    "Expire": 7200,
    "RefreshExpire": 604800,
    "IsRedis": true,
    "RedisConnectionString": "localhost:6379,password=yourpassword"
  }
}

// 使用配置文件
builder.Services.AddJwt(options =>
{
    builder.Configuration.GetSection("JwtOptions").Bind(options);
});
```

## 📊 缓存结构

### Redis缓存键
```
jwt:token:access:{token}                    # AccessToken信息
jwt:token:refresh:{token}                   # RefreshToken信息  
jwt:token:bind:{refreshToken}               # RefreshToken绑定关系
jwt:token:bind_user:{userId}:{clientType}   # 用户设备绑定
jwt:user:tokens:{userId}                    # 用户Token列表 (新增)
jwt:payload:{refreshToken}                  # Token负载信息
```

### 内存缓存
- 使用 `MemoryCache` 存储Token信息
- 用户级别的 `SemaphoreSlim` 保证并发安全
- 自动清理过期Token和空的信号量

## 🛡️ 安全特性

### Token安全
- **哈希保护**：日志中使用Token哈希值，避免敏感信息泄露
- **过期控制**：支持AccessToken和RefreshToken不同过期时间
- **延时删除**：RefreshToken刷新时延时删除旧Token，避免并发问题
- **签名验证**：支持多种HMAC算法进行Token签名验证

### 并发安全
- **用户级锁**：每个用户独立的信号量，避免锁竞争
- **原子操作**：Redis环境下使用原生Set操作保证原子性
- **内存保护**：MemoryCache环境下的完整并发控制

## 🔧 故障排除

### 常见问题

1. **Token验证失败**
   ```csharp
   // 检查Secret配置是否正确
   // 确保Issuer和Audience匹配
   // 验证Token是否过期
   ```

2. **Redis连接问题**
   ```csharp
   // 检查Redis连接字符串
   // 确保Redis服务正在运行
   // 验证网络连接和防火墙设置
   ```

3. **并发问题**
   ```csharp
   // 确保正确配置了IsRedis选项
   // 检查是否有死锁情况
   // 监控信号量的使用情况
   ```

## 📈 性能优化

### 缓存优化
- 使用Redis集群提高可用性
- 合理设置Token过期时间
- 定期清理过期Token

### 并发优化
- 用户级别的锁粒度
- 异步操作支持
- 连接池配置

## 🤝 贡献

欢迎提交Issue和Pull Request来帮助改进这个项目。

## 📞 支持

如果您在使用过程中遇到问题，请通过以下方式获取支持：
- 提交GitHub Issue
- 查看项目文档
- 联系技术支持团队