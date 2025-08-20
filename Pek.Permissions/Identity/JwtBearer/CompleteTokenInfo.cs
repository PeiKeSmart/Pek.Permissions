using Pek.Security;

namespace Pek.Permissions.Identity.JwtBearer;

/// <summary>
/// 完整的Token信息，包含所有相关数据，减少多次缓存查询
/// </summary>
public class CompleteTokenInfo
{
    /// <summary>
    /// 访问令牌信息
    /// </summary>
    public JsonWebToken? AccessToken { get; set; }

    /// <summary>
    /// 刷新令牌信息
    /// </summary>
    public RefreshToken? RefreshToken { get; set; }

    /// <summary>
    /// 设备绑定信息
    /// </summary>
    public DeviceTokenBindInfo? DeviceBindInfo { get; set; }

    /// <summary>
    /// Token是否存在
    /// </summary>
    public bool TokenExists { get; set; }

    /// <summary>
    /// Token是否已过期
    /// </summary>
    public bool IsExpired { get; set; }

    /// <summary>
    /// 用户ID
    /// </summary>
    public string UserId { get; set; } = string.Empty;

    /// <summary>
    /// 客户端类型
    /// </summary>
    public string ClientType { get; set; } = string.Empty;

    /// <summary>
    /// 设备ID
    /// </summary>
    public string DeviceId { get; set; } = string.Empty;

    /// <summary>
    /// 缓存时间戳
    /// </summary>
    public DateTime CachedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// 缓存是否有效（避免长时间缓存）
    /// </summary>
    public bool IsCacheValid => DateTime.UtcNow.Subtract(CachedAt).TotalMinutes < 2;
}
