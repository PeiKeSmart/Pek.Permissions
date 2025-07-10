using Pek.Security;

namespace Pek.Permissions.Identity.JwtBearer;

/// <summary>
/// 用户Token管理服务
/// </summary>
public interface IUserTokenService
{
    /// <summary>
    /// 获取用户的所有活跃Token
    /// </summary>
    /// <param name="userId">用户标识</param>
    IEnumerable<UserTokenInfo> GetUserTokens(String userId);

    /// <summary>
    /// 强制用户下线（撤销所有Token）
    /// </summary>
    /// <param name="userId">用户标识</param>
    void ForceUserOffline(String userId);

    /// <summary>
    /// 撤销用户的指定Token
    /// </summary>
    /// <param name="userId">用户标识</param>
    /// <param name="accessToken">访问令牌</param>
    void RevokeUserToken(String userId, String accessToken);

    /// <summary>
    /// 根据Token获取用户ID
    /// </summary>
    /// <param name="accessToken">访问令牌</param>
    String GetUserIdByToken(String accessToken);

    /// <summary>
    /// 获取用户Token数量
    /// </summary>
    /// <param name="userId">用户标识</param>
    Int32 GetUserTokenCount(String userId);
}

/// <summary>
/// 用户Token信息
/// </summary>
[Serializable]
public class UserTokenInfo
{
    /// <summary>
    /// 用户ID
    /// </summary>
    public String UserId { get; set; }

    /// <summary>
    /// 访问令牌
    /// </summary>
    public String AccessToken { get; set; }

    /// <summary>
    /// 刷新令牌
    /// </summary>
    public String RefreshToken { get; set; }

    /// <summary>
    /// 客户端类型
    /// </summary>
    public String ClientType { get; set; }

    /// <summary>
    /// 设备ID
    /// </summary>
    public String DeviceId { get; set; }

    /// <summary>
    /// 访问令牌过期时间（UTC时间戳）
    /// </summary>
    public Int64 AccessTokenUtcExpires { get; set; }

    /// <summary>
    /// 刷新令牌过期时间（UTC时间戳）
    /// </summary>
    public Int64 RefreshUtcExpires { get; set; }

    /// <summary>
    /// 用户ID（兼容现有JsonWebToken）
    /// </summary>
    public Int32 UId { get; set; }

    /// <summary>
    /// 访问令牌过期时间
    /// </summary>
    public DateTime AccessTokenExpires => DateTimeOffset.FromUnixTimeMilliseconds(AccessTokenUtcExpires).DateTime;

    /// <summary>
    /// 刷新令牌过期时间
    /// </summary>
    public DateTime RefreshTokenExpires => DateTimeOffset.FromUnixTimeMilliseconds(RefreshUtcExpires).DateTime;

    /// <summary>
    /// 是否已过期
    /// </summary>
    public Boolean IsExpired => DateTime.UtcNow > AccessTokenExpires;

    /// <summary>
    /// Token哈希值（用于安全日志记录）
    /// </summary>
    public String AccessTokenHash => AccessToken?.GetHashCode().ToString("X8");
}
