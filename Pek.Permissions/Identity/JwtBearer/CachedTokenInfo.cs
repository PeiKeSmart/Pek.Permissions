using System.Security.Claims;

using NewLife.Web;

namespace Pek.Permissions.Identity.JwtBearer;

/// <summary>
/// 缓存的Token信息，避免重复解码
/// </summary>
public class CachedTokenInfo
{
    /// <summary>
    /// 原始Token字符串
    /// </summary>
    public string Token { get; set; } = string.Empty;

    /// <summary>
    /// JWT构建器（包含解码后的信息）
    /// </summary>
    public JwtBuilder JwtBuilder { get; set; } = null!;

    /// <summary>
    /// Claims主体
    /// </summary>
    public ClaimsPrincipal ClaimsPrincipal { get; set; } = null!;

    /// <summary>
    /// JWT Header信息
    /// </summary>
    public IDictionary<string, object>? Header { get; set; }

    /// <summary>
    /// JWT Payload信息
    /// </summary>
    public IDictionary<string, object>? Payload { get; set; }

    /// <summary>
    /// 是否已验证签名
    /// </summary>
    public bool IsSignatureValid { get; set; }

    /// <summary>
    /// 解码时间戳（用于缓存失效）
    /// </summary>
    public DateTime DecodedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// 检查缓存是否仍然有效（避免长时间缓存过期Token）
    /// </summary>
    public bool IsCacheValid => DateTime.UtcNow.Subtract(DecodedAt).TotalMinutes < 5;

    /// <summary>
    /// 生成缓存键，避免重复字符串拼接
    /// </summary>
    /// <param name="token">Token字符串</param>
    /// <returns>缓存键</returns>
    public static string GetCacheKey(string token) => $"CachedTokenInfo_{token.GetHashCode()}";
}
