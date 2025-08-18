using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Pek.Permissions.Identity.JwtBearer;
using System.Security.Claims;

namespace Pek.Permissions.Examples;

/// <summary>
/// 设备ID验证测试控制器
/// </summary>
[ApiController]
[Route("api/[controller]")]
public class DeviceIdValidationTestController : ControllerBase
{
    private readonly IJsonWebTokenBuilder _tokenBuilder;
    private readonly ILogger<DeviceIdValidationTestController> _logger;

    public DeviceIdValidationTestController(
        IJsonWebTokenBuilder tokenBuilder,
        ILogger<DeviceIdValidationTestController> logger)
    {
        _tokenBuilder = tokenBuilder;
        _logger = logger;
    }

    /// <summary>
    /// 创建Token测试 - 正常情况
    /// </summary>
    [HttpPost("create-token")]
    public IActionResult CreateToken([FromBody] CreateTokenRequest request)
    {
        try
        {
            var payload = new Dictionary<string, string>
            {
                [ClaimTypes.Sid] = request.UserId,
                ["From"] = "test",
                ["clientType"] = request.ClientType ?? "web"
            };

            // 如果提供了clientId，添加到payload中
            if (!string.IsNullOrEmpty(request.ClientId))
            {
                payload["clientId"] = request.ClientId;
            }

            var token = _tokenBuilder.Create(payload);

            return Ok(new
            {
                success = true,
                message = "Token创建成功",
                data = new
                {
                    accessToken = token.AccessToken,
                    refreshToken = token.RefreshToken,
                    accessTokenExpires = token.AccessTokenUtcExpires,
                    refreshTokenExpires = token.RefreshUtcExpires
                }
            });
        }
        catch (UnauthorizedAccessException ex)
        {
            return BadRequest(new
            {
                success = false,
                message = ex.Message,
                errorCode = "DEVICE_ID_MISMATCH"
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "创建Token时发生错误");
            return StatusCode(500, new
            {
                success = false,
                message = "服务器内部错误",
                error = ex.Message
            });
        }
    }

    /// <summary>
    /// 获取当前设备ID
    /// </summary>
    [HttpGet("device-id")]
    public IActionResult GetDeviceId()
    {
        var deviceId = GetCurrentDeviceId();
        return Ok(new
        {
            success = true,
            deviceId = deviceId,
            message = "当前设备ID"
        });
    }

    /// <summary>
    /// 测试Token验证 - 需要JWT授权
    /// </summary>
    [HttpGet("validate-token")]
    [Pek.Permissions.JwtAuthorize("test")]
    public IActionResult ValidateToken()
    {
        var userId = User.FindFirst(ClaimTypes.Sid)?.Value;
        var deviceId = GetCurrentDeviceId();
        
        return Ok(new
        {
            success = true,
            message = "Token验证成功",
            data = new
            {
                userId = userId,
                currentDeviceId = deviceId,
                claims = User.Claims.Select(c => new { c.Type, c.Value }).ToArray()
            }
        });
    }

    /// <summary>
    /// 模拟设备ID不匹配的情况
    /// </summary>
    [HttpPost("simulate-mismatch")]
    public IActionResult SimulateMismatch([FromBody] SimulateMismatchRequest request)
    {
        try
        {
            // 创建一个包含错误clientId的payload
            var payload = new Dictionary<string, string>
            {
                [ClaimTypes.Sid] = request.UserId,
                ["From"] = "test",
                ["clientType"] = "web",
                ["clientId"] = request.FakeClientId // 故意使用错误的clientId
            };

            var token = _tokenBuilder.Create(payload);

            return Ok(new
            {
                success = true,
                message = "这不应该成功，如果看到这个消息说明验证有问题",
                data = token
            });
        }
        catch (UnauthorizedAccessException ex)
        {
            return Ok(new
            {
                success = true,
                message = "设备ID验证正常工作",
                error = ex.Message,
                expectedBehavior = true
            });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new
            {
                success = false,
                message = "测试过程中发生意外错误",
                error = ex.Message
            });
        }
    }

    /// <summary>
    /// 获取当前设备ID的辅助方法
    /// </summary>
    private string GetCurrentDeviceId()
    {
        // 准备Session，避免未启用Session时ctx.Session直接抛出异常
        var ss = HttpContext.Features.Get<Microsoft.AspNetCore.Http.Features.ISessionFeature>()?.Session;
        if (ss != null && !ss.IsAvailable) ss = null;

        // http/https分开使用不同的Cookie名，避免站点同时支持http和https时，Cookie冲突
        var id = ss?.GetString("CubeDeviceId");
        if (string.IsNullOrEmpty(id)) id = HttpContext.Request.Cookies["CubeDeviceId"];
        if (string.IsNullOrEmpty(id)) id = HttpContext.Request.Cookies["CubeDeviceId0"];
        
        return id ?? "未设置";
    }
}

/// <summary>
/// 创建Token请求
/// </summary>
public class CreateTokenRequest
{
    /// <summary>
    /// 用户ID
    /// </summary>
    public string UserId { get; set; }

    /// <summary>
    /// 客户端类型
    /// </summary>
    public string ClientType { get; set; }

    /// <summary>
    /// 客户端ID（可选，用于测试）
    /// </summary>
    public string ClientId { get; set; }
}

/// <summary>
/// 模拟不匹配请求
/// </summary>
public class SimulateMismatchRequest
{
    /// <summary>
    /// 用户ID
    /// </summary>
    public string UserId { get; set; }

    /// <summary>
    /// 伪造的客户端ID
    /// </summary>
    public string FakeClientId { get; set; }
}
