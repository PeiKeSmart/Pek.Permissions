﻿using Pek.Security;

namespace Pek.Permissions.Identity.JwtBearer;

/// <summary>
/// Jwt令牌存储器
/// </summary>
public interface IJsonWebTokenStore
{
    /// <summary>
    /// 获取刷新令牌
    /// </summary>
    /// <param name="token">刷新令牌</param>
    RefreshToken GetRefreshToken(String token);

    /// <summary>
    /// 保存刷新令牌
    /// </summary>
    /// <param name="token">刷新令牌</param>
    void SaveRefreshToken(RefreshToken token);

    /// <summary>
    /// 移除刷新令牌
    /// </summary>
    /// <param name="token">刷新令牌</param>
    void RemoveRefreshToken(String token);

    /// <summary>
    /// 延时移除刷新令牌
    /// </summary>
    /// <param name="token">刷新令牌</param>
    /// <param name="expire">延时时间。秒</param>
    void RemoveRefreshToken(String token, Int32 expire);

    /// <summary>
    /// 获取访问令牌
    /// </summary>
    /// <param name="token">访问令牌</param>
    JsonWebToken GetToken(String token);

    /// <summary>
    /// 移除访问令牌
    /// </summary>
    /// <param name="token">访问令牌</param>
    void RemoveToken(String token);

    /// <summary>
    /// 延时移除访问令牌
    /// </summary>
    /// <param name="token">访问令牌</param>
    /// <param name="expire">延时时间。秒</param>
    void RemoveToken(String token, Int32 expire);

    /// <summary>
    /// 保存访问令牌
    /// </summary>
    /// <param name="token">令牌</param>
    /// <param name="expires">过期时间</param>
    void SaveToken(JsonWebToken token, DateTime expires);

    /// <summary>
    /// 是否存在访问令牌
    /// </summary>
    /// <param name="token">访问令牌</param>
    bool ExistsToken(String token);

    /// <summary>
    /// 绑定用户设备令牌
    /// </summary>
    /// <param name="userId">用户标识</param>
    /// <param name="clientType">客户端类型</param>
    /// <param name="info">设备信息</param>
    /// <param name="expires">过期时间</param>
    void BindUserDeviceToken(String userId, String clientType, DeviceTokenBindInfo info, DateTime expires);

    /// <summary>
    /// 获取用户设备令牌
    /// </summary>
    /// <param name="userId">用户标识</param>
    /// <param name="clientType">客户端类型</param>
    DeviceTokenBindInfo GetUserDeviceToken(String userId, String clientType);

    #region 用户Token管理

    /// <summary>
    /// 添加用户Token关联
    /// </summary>
    /// <param name="userId">用户标识</param>
    /// <param name="accessToken">访问令牌</param>
    /// <param name="expires">过期时间</param>
    void AddUserToken(String userId, String accessToken, DateTime expires);

    /// <summary>
    /// 移除用户Token关联
    /// </summary>
    /// <param name="userId">用户标识</param>
    /// <param name="accessToken">访问令牌</param>
    void RemoveUserToken(String userId, String accessToken);

    /// <summary>
    /// 获取用户的所有AccessToken
    /// </summary>
    /// <param name="userId">用户标识</param>
    IEnumerable<String> GetUserAccessTokens(String userId);

    /// <summary>
    /// 移除用户的所有Token
    /// </summary>
    /// <param name="userId">用户标识</param>
    void RemoveAllUserTokens(String userId);

    #endregion
}
