using Pek.Security;

namespace Pek.Permissions.Identity.JwtBearer;

/// <summary>
/// JWT构建器工厂，避免重复创建和配置
/// </summary>
internal static class JwtBuilderFactory
{
    /// <summary>
    /// 创建JWT构建器
    /// </summary>
    /// <param name="secret">密钥配置（格式：算法:密钥）</param>
    /// <returns>配置好的JWT构建器，如果配置无效则返回null</returns>
    public static JwtBuilder? CreateBuilder(string secret)
    {
        if (string.IsNullOrWhiteSpace(secret))
            return null;

        var parts = secret.Split(':');
        if (parts.Length < 2)
            return null;

        return new JwtBuilder
        {
            Algorithm = parts[0],
            Secret = parts[1],
        };
    }

    /// <summary>
    /// 验证Token签名
    /// </summary>
    /// <param name="token">JWT Token</param>
    /// <param name="secret">密钥配置</param>
    /// <returns>验证结果</returns>
    public static bool ValidateSignature(string token, string secret)
    {
        var builder = CreateBuilder(secret);
        return builder?.TryDecode(token, out _) == true;
    }
}
