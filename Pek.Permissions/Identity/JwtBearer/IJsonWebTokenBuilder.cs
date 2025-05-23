﻿using Pek.Security;

namespace Pek.Permissions.Identity.JwtBearer;

/// <summary>
/// Jwt令牌构建器
/// </summary>
public interface IJsonWebTokenBuilder
{
    /// <summary>
    /// 创建令牌
    /// </summary>
    /// <param name="payload">负载</param>
    JsonWebToken Create(IDictionary<String, String> payload);

    /// <summary>
    /// 创建令牌
    /// </summary>
    /// <param name="payload">负载</param>
    /// <param name="AccessExpireMinutes">访问令牌有效期分钟数</param>
    /// <param name="RefreshExpireMinutes">刷新令牌有效期分钟数</param>
    JsonWebToken Create(IDictionary<String, String> payload, Double RefreshExpireMinutes, Double AccessExpireMinutes = 0);

    /// <summary>
    /// 创建令牌
    /// </summary>
    /// <param name="payload">负载</param>
    /// <param name="options">Jwt选项配置</param>
    JsonWebToken Create(IDictionary<String, String> payload, JwtOptions options);

    /// <summary>
    /// 刷新令牌
    /// </summary>
    /// <param name="refreshToken">刷新令牌</param>
    JsonWebToken Refresh(String refreshToken);

    /// <summary>
    /// 刷新令牌
    /// </summary>
    /// <param name="refreshToken">刷新令牌</param>
    /// <param name="options"></param>
    JsonWebToken Refresh(String refreshToken, JwtOptions options);

    /// <summary>
    /// 刷新令牌
    /// </summary>
    /// <param name="refreshToken">刷新令牌</param>
    /// <param name="RefreshExpireMinutes">刷新令牌有效期分钟数</param>
    JsonWebToken Refresh(String refreshToken, Double RefreshExpireMinutes);

    /// <summary>
    /// 刷新令牌，延时清理数据
    /// </summary>
    /// <param name="refreshToken">刷新令牌</param>
    /// <param name="expire">延时时间。秒</param>
    JsonWebToken Refresh(String refreshToken, Int32 expire);

    /// <summary>
    /// 刷新令牌，延时清理数据
    /// </summary>
    /// <param name="refreshToken">刷新令牌</param>
    /// <param name="expire">延时时间。秒</param>
    /// <param name="RefreshExpireMinutes">刷新令牌有效期分钟数</param>
    JsonWebToken Refresh(String refreshToken, Int32 expire, Double RefreshExpireMinutes);
}
