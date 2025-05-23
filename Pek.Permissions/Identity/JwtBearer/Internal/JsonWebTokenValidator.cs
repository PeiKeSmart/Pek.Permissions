﻿using NewLife;
using NewLife.Serialization;

using Pek.Helpers;
using Pek.Security;

namespace Pek.Permissions.Identity.JwtBearer.Internal;

/// <summary>
/// Jwt令牌校验器
/// </summary>
internal sealed class JsonWebTokenValidator : IJsonWebTokenValidator
{
    /// <summary>
    /// 校验
    /// </summary>
    /// <param name="encodeJwt">加密后的Jwt令牌</param>
    /// <param name="options">Jwt选项配置</param>
    /// <param name="validatePayload">校验负载</param>
    public Boolean Validate(String encodeJwt, JwtOptions options, Func<IDictionary<String, Object>, JwtOptions, Boolean> validatePayload)
    {
        //if (options.Secret.IsNullOrWhiteSpace())
        //    throw new ArgumentNullException(nameof(options.Secret),
        //        $@"{nameof(options.Secret)}为Null或空字符串。请在""appsettings.json""配置""{nameof(JwtOptions)}""节点及其子节点""{nameof(JwtOptions.Secret)}""");
        var jwtArray = encodeJwt.Split('.');
        if (jwtArray.Length < 3)
            return false;
        var header = jwtArray[0].ToBase64().ToStr().DecodeJson();
        var payload = jwtArray[1].ToBase64().ToStr().DecodeJson();

        DHWeb.HttpContext.Items["jwt-header"] = header;
        DHWeb.HttpContext.Items["jwt-payload"] = payload;

        //// 首先验证签名是否正确
        //var ss = options.Secret.Split(':');
        //var jwt = new JwtBuilder
        //{
        //    Algorithm = ss[0],
        //    Secret = ss[1],
        //};
        //if (!jwt.TryDecode(encodeJwt, out _))
        //    return false;

        //var claims = Helper.ToClaims(jwt.Items);
        //DHWeb.HttpContext.User = new ClaimsPrincipal(new ClaimsIdentity(claims, "jwt"));

        //var hs256 = new HMACSHA256(Encoding.UTF8.GetBytes(options.Secret));
        //var sign = Base64UrlEncoder.Encode(
        //    hs256.ComputeHash(Encoding.UTF8.GetBytes(string.Concat(jwtArray[0], ".", jwtArray[1]))));
        //// 签名不正确直接返回
        //if (!string.Equals(jwtArray[2], sign))
        //    return false;
        //// 其次验证是否在有效期内
        ////var now = ToUnixEpochDate(DateTime.UtcNow);
        ////if (!(now >= long.Parse(payload["nbf"].ToString()) && now < long.Parse(payload["exp"].ToString())))
        ////    return false;
        //// 进行自定义验证
        
        return validatePayload(payload, options);
    }
}
