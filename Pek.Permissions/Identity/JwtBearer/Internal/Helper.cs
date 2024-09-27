using System.Reflection;
using System.Security.Claims;
using System.Text;

using NewLife;
using NewLife.Remoting;
using NewLife.Security;
using NewLife.Web;

using Pek.Security;

namespace DH.Permissions.Identity.JwtBearer.Internal;

/// <summary>
/// JwtBearer帮助类
/// </summary>
internal static class Helper
{
    /// <summary>
    /// 转换为声明列表
    /// </summary>
    /// <param name="dictionary">字典</param>
    public static IEnumerable<Claim> ToClaims(IDictionary<string, string> dictionary) =>
        dictionary.Keys.Select(key => new Claim(key, dictionary[key]?.ToString()));

    /// <summary>
    /// 转换为声明列表
    /// </summary>
    /// <param name="dictionary">字典</param>
    public static IEnumerable<Claim> ToClaims(IDictionary<string, Object> dictionary) =>
        dictionary.Keys.Select(key => new Claim(key, dictionary[key]?.ToString()));

    /// <summary>颁发令牌</summary>
    /// <param name="name"></param>
    /// <param name="secret"></param>
    /// <param name="expire"></param>
    /// <param name="id"></param>
    /// <returns></returns>
    public static TokenModel IssueToken(String name, String secret, Int32 expire, String id = null)
    {
        if (id.IsNullOrEmpty()) id = Rand.NextString(8);

        // 颁发令牌
        var ss = secret.Split(':');
        var jwt = new JwtBuilder
        {
            Issuer = Assembly.GetEntryAssembly()?.GetName().Name,
            Subject = name,
            Id = id,
            Expire = DateTime.Now.AddSeconds(expire),

            Algorithm = ss[0],
            Secret = ss[1],
        };

        var payload = new Dictionary<String, String>();
        payload["name"] = name;
        payload["test"] = id;

        return new TokenModel
        {
            AccessToken = jwt.Encode(payload),
            TokenType = jwt.Type ?? "JWT",
            ExpireIn = expire,
            RefreshToken = jwt.Encode(payload),
        };
    }

    /// <summary>验证并续发新令牌，过期前10分钟才能续发</summary>
    /// <param name="name"></param>
    /// <param name="token"></param>
    /// <param name="secret"></param>
    /// <param name="expire"></param>
    /// <returns></returns>
    public static TokenModel ValidAndIssueToken(String name, String token, String secret, Int32 expire)
    {
        if (token.IsNullOrEmpty()) return null;

        // 令牌有效期检查，10分钟内过期者，重新颁发令牌
        var ss = secret.Split(':');
        var jwt = new JwtBuilder
        {
            Algorithm = ss[0],
            Secret = ss[1],
        };
        if (!jwt.TryDecode(token, out _)) return null;

        return DateTime.Now.AddMinutes(10) > jwt.Expire ? IssueToken(name, secret, expire) : null;
    }

    /// <summary>解码令牌</summary>
    /// <param name="token"></param>
    /// <param name="tokenSecret"></param>
    /// <returns></returns>
    public static (JwtBuilder, Exception) DecodeTokenWithError(String token, String tokenSecret)
    {
        if (token.IsNullOrEmpty()) throw new ArgumentNullException(nameof(token));

        // 解码令牌
        var ss = tokenSecret.Split(':');
        var jwt = new JwtBuilder
        {
            Algorithm = ss[0],
            Secret = ss[1],
        };

        Exception ex = null;
        if (!jwt.TryDecode(token, out var message)) ex = new ApiException(403, $"非法访问[{jwt.Subject}]，{message}");

        return (jwt, ex);
    }
}

/// <summary>
/// Jwt令牌类型
/// </summary>
internal enum JsonWebTokenType
{
    /// <summary>
    /// 访问令牌
    /// </summary>
    AccessToken,

    /// <summary>
    /// 刷新令牌
    /// </summary>
    RefreshToken
}
