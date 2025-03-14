﻿using Microsoft.AspNetCore.Authorization;

using Pek.Security;

namespace Pek.Permissions.Authorization.Policies;

/// <summary>
/// JWT授权请求
/// </summary>
public interface IJsonWebTokenAuthorizationRequirement : IAuthorizationRequirement
{
    /// <summary>
    /// 设置校验函数
    /// </summary>
    /// <param name="func">校验函数</param>
    IJsonWebTokenAuthorizationRequirement SetValidateFunc(
        Func<IDictionary<String, Object>, JwtOptions, Boolean> func);
}
