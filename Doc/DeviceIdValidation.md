# 设备ID验证功能说明

## 概述

本功能实现了基于设备ID的JWT Token验证机制，确保Token只能在创建它的设备上使用，有效防止Token跨设备滥用和会话劫持攻击。

## 核心特性

### 🔒 设备级别的Token绑定
- Token创建时自动绑定到当前设备
- 使用持久化Cookie存储设备ID（10年有效期）
- 支持HTTP/HTTPS环境下的设备识别

### 🛡️ 多层安全验证
1. **Token创建验证**：确保clientId与真实设备ID一致
2. **Token使用验证**：每次API调用都验证设备ID匹配性
3. **单设备登录**：可配置是否允许同一用户在多设备登录

### 📊 完整的安全日志
- 记录Token创建事件
- 记录设备ID不匹配的安全警告
- 包含客户端IP、User-Agent等详细信息

## 技术实现

### 设备ID生成机制
```csharp
// 设备ID获取优先级：
// 1. Session中的CubeDeviceId
// 2. Cookie中的CubeDeviceId (HTTPS)
// 3. Cookie中的CubeDeviceId0 (HTTP)
// 4. 自动生成新的16位随机字符串
```

### Token创建流程
1. 获取当前设备的真实设备ID
2. 验证请求中的clientId与设备ID是否一致
3. 如果不一致，记录安全日志并拒绝创建
4. 创建Token并绑定到设备

### Token验证流程
1. 解析Token中的clientId
2. 获取当前请求的设备ID
3. 比较两者是否一致
4. 不一致则记录安全日志并拒绝访问

## 配置说明

### 启用单设备登录
```json
{
  "JwtOptions": {
    "SingleDeviceEnabled": true,
    "Secret": "HS256:your-secret-key",
    "Issuer": "your-issuer",
    "AccessExpireMinutes": 30,
    "RefreshExpireMinutes": 1440
  }
}
```

### 服务注册
```csharp
// 在Startup.cs或Program.cs中
services.AddJwt(options =>
{
    options.Secret = "HS256:your-secret-key";
    options.SingleDeviceEnabled = true;
    // 其他配置...
});
```

## API测试示例

### 1. 获取当前设备ID
```http
GET /api/DeviceIdValidationTest/device-id
```

### 2. 创建Token（正常情况）
```http
POST /api/DeviceIdValidationTest/create-token
Content-Type: application/json

{
  "userId": "user123",
  "clientType": "web"
}
```

### 3. 创建Token（指定clientId）
```http
POST /api/DeviceIdValidationTest/create-token
Content-Type: application/json

{
  "userId": "user123",
  "clientType": "web",
  "clientId": "your-device-id"
}
```

### 4. 验证Token
```http
GET /api/DeviceIdValidationTest/validate-token
Authorization: Bearer your-jwt-token
```

### 5. 模拟设备ID不匹配
```http
POST /api/DeviceIdValidationTest/simulate-mismatch
Content-Type: application/json

{
  "userId": "user123",
  "fakeClientId": "fake-device-id"
}
```

## 安全日志格式

### Token创建日志
```json
{
  "eventType": "TokenCreated",
  "timestamp": "2024-01-01T12:00:00Z",
  "userId": "user123",
  "deviceId": "abc123def456",
  "clientType": "web",
  "clientIP": "192.168.1.100",
  "userAgent": "Mozilla/5.0..."
}
```

### 设备ID不匹配日志
```json
{
  "eventType": "DeviceIdMismatch",
  "timestamp": "2024-01-01T12:00:00Z",
  "userId": "user123",
  "tokenClientId": "fake-device-id",
  "currentDeviceId": "abc123def456",
  "clientIP": "192.168.1.100",
  "userAgent": "Mozilla/5.0...",
  "requestPath": "/api/test",
  "requestMethod": "GET",
  "additionalInfo": {
    "action": "TokenValidation",
    "method": "ResultHandle"
  }
}
```

## 错误码说明

| 错误码 | 说明 |
|--------|------|
| 40001 | Token不存在或已失效 |
| 40002 | Token验证失败 |
| 40003 | Token已过期 |
| 40004 | 该账号已在其它设备登录 |
| 40005 | 设备标识不匹配，Token无法在此设备使用 |

## 最佳实践

### 1. 前端集成
- 确保前端不要手动设置clientId
- 让系统自动获取和验证设备ID
- 处理设备ID不匹配的错误情况

### 2. 安全监控
- 监控设备ID不匹配的日志
- 设置告警机制检测异常行为
- 定期分析安全日志

### 3. 用户体验
- 在设备ID不匹配时提供友好的错误提示
- 考虑提供重新登录的选项
- 在多设备场景下给用户明确的提示

## 注意事项

1. **Cookie依赖**：功能依赖浏览器Cookie，确保Cookie未被禁用
2. **HTTPS环境**：HTTPS环境下Cookie设置更严格，兼容性更好
3. **Session支持**：如果启用了Session，会优先使用Session存储设备ID
4. **性能影响**：每次请求都会进行设备ID验证，对性能影响很小
5. **向后兼容**：现有Token在升级后仍可正常使用，但不会有设备绑定保护

## 故障排除

### 常见问题
1. **设备ID获取失败**：检查Cookie是否被禁用或清除
2. **验证总是失败**：检查系统时间是否同步
3. **跨域问题**：确保Cookie的Domain和SameSite设置正确

### 调试方法
1. 查看浏览器开发者工具中的Cookie
2. 检查服务器日志中的安全事件
3. 使用测试API验证设备ID获取和验证流程
