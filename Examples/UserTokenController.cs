using Microsoft.AspNetCore.Mvc;
using Pek.Permissions.Identity.JwtBearer;

namespace Pek.Permissions.Examples;

/// <summary>
/// 用户Token管理示例控制器
/// </summary>
[ApiController]
[Route("api/[controller]")]
public class UserTokenController : ControllerBase
{
    private readonly IUserTokenService _userTokenService;
    private readonly IJsonWebTokenBuilder _tokenBuilder;

    public UserTokenController(IUserTokenService userTokenService, IJsonWebTokenBuilder tokenBuilder)
    {
        _userTokenService = userTokenService;
        _tokenBuilder = tokenBuilder;
    }

    /// <summary>
    /// 获取用户的所有Token
    /// </summary>
    [HttpGet("{userId}/tokens")]
    public IActionResult GetUserTokens(string userId)
    {
        var tokens = _userTokenService.GetUserTokens(userId);
        return Ok(new
        {
            userId,
            tokenCount = tokens.Count(),
            tokens = tokens.Select(t => new
            {
                tokenHash = t.AccessTokenHash,
                clientType = t.ClientType,
                deviceId = t.DeviceId,
                accessTokenExpires = t.AccessTokenExpires,
                refreshTokenExpires = t.RefreshTokenExpires,
                isExpired = t.IsExpired
            })
        });
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

/// <summary>
/// 撤销Token请求
/// </summary>
public class RevokeTokenRequest
{
    public string AccessToken { get; set; }
}

/// <summary>
/// 查找用户请求
/// </summary>
public class FindUserRequest
{
    public string AccessToken { get; set; }
}
