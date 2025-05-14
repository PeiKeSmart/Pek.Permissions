using Microsoft.AspNetCore.Authorization;

namespace Pek.Permissions;

/// <summary>
/// 自定义 Jwt 授权特性。
/// 用于指定来源，支持同一系统多个 Jwt 的授权需求。
/// </summary>
public class JwtAuthorizeAttribute : AuthorizeAttribute
{
    /// <summary>
    /// 来源，方便同一系统多个Jwt使用
    /// </summary>
    public String From { get; set; }

    /// <summary>
    /// 初始化 <see cref="JwtAuthorizeAttribute"/> 类的新实例。
    /// </summary>
    /// <param name="from">Jwt 来源标识。</param>
    public JwtAuthorizeAttribute(String from) { From = from; Policy = "jwt"; }
}