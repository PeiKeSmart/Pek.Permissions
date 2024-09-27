using NewLife;
using System.Reflection;

using NewLife.Log;
using NewLife.Security;
using NewLife.Web;
using NewLife.Serialization;
using NewLife.Remoting;

namespace JwtDemo;

internal class Program
{
    static void Main(string[] args)
    {
        XTrace.UseConsole();

        var JwtSecret = $"HS256:{Rand.NextString(16)}";

        var token = IssueToken("admin", JwtSecret, 540, "1");
        XTrace.WriteLine($"获取到的数据：{token.ToJson()}");

        var s =  DecodeTokenWithError(token.AccessToken!, JwtSecret);
        XTrace.WriteLine($"获取到的数据1：{s.Item1.Subject}");

        foreach(var item in s.Item1.Items)
        {
            XTrace.WriteLine($"获取到的数据1：{item.Key}:{item.Value}");
        }

        var token2 = ValidAndIssueToken("admin", token.AccessToken!, JwtSecret, 540);
        XTrace.WriteLine($"获取到的数据：{token2?.ToJson()}");

        s = DecodeTokenWithError(token2?.AccessToken!, JwtSecret);
        XTrace.WriteLine($"获取到的数据1：{s.Item1.Subject}");

        JwtSecret = "HS256:qyzgLoRi9PvsWyMDllQoCIQsxM";
        var token1 = "eyJhbGciOiJIUzI1NiJ9.eyJjbGllbnRJZCI6IjEiLCJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9zaWQiOiIxIiwiaHR0cDovL3NjaGVtYXMueG1sc29hcC5vcmcvd3MvMjAwNS8wNS9pZGVudGl0eS9jbGFpbXMvbmFtZWlkZW50aWZpZXIiOiJhZG1pbiIsImlzcyI6ImRpbmdfaWRlbnRpdHkiLCJzdWIiOiIxIiwiZXhwIjoxNzI3MzI1MzUxLCJpYXQiOjE3MjczMTgxNTEsImp0aSI6IjEifQ.ZZWVBbOqYTpJNoE7aHgmrlrwmLJbm2Owv2B1U4oow08";
        s = DecodeTokenWithError(token1, JwtSecret);

        foreach (var item in s.Item1.Items)
        {
            XTrace.WriteLine($"获取到的数据2：{item.Key}:{item.Value}");
        }

        XTrace.WriteLine($"获取到的数据2：{s.Item1.Subject}");

        var jwtArray = token1.Split('.');
        var payload = jwtArray[1].ToBase64().ToStr().DecodeJson();
        foreach (var item in payload!)
        {
            XTrace.WriteLine($"获取到的数据3：{item.Key}:{item.Value}");
        }
    }

    /// <summary>颁发令牌</summary>
    /// <param name="name"></param>
    /// <param name="secret"></param>
    /// <param name="expire"></param>
    /// <param name="id"></param>
    /// <returns></returns>
    public static TokenModel IssueToken(String name, String secret, Int32 expire, String? id = null)
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
    public static TokenModel? ValidAndIssueToken(String name, String token, String secret, Int32 expire)
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
    public static (JwtBuilder, Exception?) DecodeTokenWithError(String token, String tokenSecret)
    {
        if (token.IsNullOrEmpty()) throw new ArgumentNullException(nameof(token));

        // 解码令牌
        var ss = tokenSecret.Split(':');
        var jwt = new JwtBuilder
        {
            Algorithm = ss[0],
            Secret = ss[1],
        };

        Exception? ex = null;
        if (!jwt.TryDecode(token, out var message)) ex = new ApiException(403, $"非法访问[{jwt.Subject}]，{message}");

        return (jwt, ex);
    }

}
