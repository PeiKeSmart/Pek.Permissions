using Microsoft.AspNetCore.Http;
using NewLife.Log;
using System.Text.Json;

namespace Pek.Permissions.Security;

/// <summary>
/// 安全日志记录器
/// </summary>
public static class SecurityLogger
{
    /// <summary>
    /// 记录设备ID不匹配的安全事件
    /// </summary>
    /// <param name="httpContext">HTTP上下文</param>
    /// <param name="tokenClientId">Token中的ClientId</param>
    /// <param name="currentDeviceId">当前设备ID</param>
    /// <param name="userId">用户ID</param>
    /// <param name="additionalInfo">附加信息</param>
    public static void LogDeviceIdMismatch(HttpContext httpContext, string tokenClientId, string currentDeviceId, string userId, object additionalInfo = null)
    {
        var logData = new
        {
            EventType = "DeviceIdMismatch",
            Timestamp = DateTime.UtcNow,
            UserId = userId,
            TokenClientId = tokenClientId,
            CurrentDeviceId = currentDeviceId,
            ClientIP = GetClientIP(httpContext),
            UserAgent = httpContext?.Request?.Headers["User-Agent"].ToString(),
            RequestPath = httpContext?.Request?.Path.ToString(),
            RequestMethod = httpContext?.Request?.Method,
            Referer = httpContext?.Request?.Headers["Referer"].ToString(),
            AdditionalInfo = additionalInfo
        };

        var logMessage = JsonSerializer.Serialize(logData, new JsonSerializerOptions 
        { 
            WriteIndented = false,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        });

        XTrace.WriteLine($"[SECURITY_ALERT] {logMessage}");
    }

    /// <summary>
    /// 记录Token创建时的设备绑定信息
    /// </summary>
    /// <param name="httpContext">HTTP上下文</param>
    /// <param name="userId">用户ID</param>
    /// <param name="deviceId">设备ID</param>
    /// <param name="clientType">客户端类型</param>
    public static void LogTokenCreated(HttpContext httpContext, string userId, string deviceId, string clientType)
    {
        var logData = new
        {
            EventType = "TokenCreated",
            Timestamp = DateTime.UtcNow,
            UserId = userId,
            DeviceId = deviceId,
            ClientType = clientType,
            ClientIP = GetClientIP(httpContext),
            UserAgent = httpContext?.Request?.Headers["User-Agent"].ToString()
        };

        var logMessage = JsonSerializer.Serialize(logData, new JsonSerializerOptions 
        { 
            WriteIndented = false,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        });

        XTrace.WriteLine($"[SECURITY_INFO] {logMessage}");
    }

    /// <summary>
    /// 记录Token验证成功的信息
    /// </summary>
    /// <param name="httpContext">HTTP上下文</param>
    /// <param name="userId">用户ID</param>
    /// <param name="deviceId">设备ID</param>
    public static void LogTokenValidated(HttpContext httpContext, string userId, string deviceId)
    {
        var logData = new
        {
            EventType = "TokenValidated",
            Timestamp = DateTime.UtcNow,
            UserId = userId,
            DeviceId = deviceId,
            ClientIP = GetClientIP(httpContext),
            RequestPath = httpContext?.Request?.Path.ToString(),
            RequestMethod = httpContext?.Request?.Method
        };

        var logMessage = JsonSerializer.Serialize(logData, new JsonSerializerOptions 
        { 
            WriteIndented = false,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        });

        XTrace.WriteLine($"[SECURITY_DEBUG] {logMessage}");
    }

    /// <summary>
    /// 获取客户端IP地址
    /// </summary>
    /// <param name="httpContext">HTTP上下文</param>
    /// <returns>客户端IP地址</returns>
    private static string GetClientIP(HttpContext httpContext)
    {
        if (httpContext == null) return "Unknown";

        // 尝试从各种可能的头部获取真实IP
        var headers = new[] { "X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP", "X-Client-IP" };
        
        foreach (var header in headers)
        {
            var value = httpContext.Request.Headers[header].FirstOrDefault();
            if (!string.IsNullOrEmpty(value))
            {
                // X-Forwarded-For 可能包含多个IP，取第一个
                var ip = value.Split(',')[0].Trim();
                if (!string.IsNullOrEmpty(ip) && ip != "unknown")
                {
                    return ip;
                }
            }
        }

        // 如果没有找到，使用连接的远程IP
        return httpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
    }
}
