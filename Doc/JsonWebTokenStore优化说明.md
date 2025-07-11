# JsonWebTokenStore 拆分实现总结

## 概述

成功对 `JsonWebTokenStore` 进行了拆分，现在可以根据 `_isRedis` 标识自动选择使用 Redis 模式或内存缓存模式来管理用户 Token。

## 主要改进

### 1. 架构优化
- **条件判断**：通过 `_isRedis` 字段区分 Redis 和内存缓存环境
- **方法拆分**：每个用户 Token 管理方法都拆分为 Redis 和 Memory 两种实现
- **统一接口**：保持原有接口不变，确保向后兼容

### 2. Redis 模式实现

#### 特点
- **原生并发安全**：利用 Redis 自身的原子操作，天然支持高并发
- **简化实现**：去除了复杂的信号量管理，代码更简洁
- **高性能**：减少了锁竞争，提升了并发性能

#### 核心方法
```csharp
private void AddUserTokenForRedis(String userId, String accessToken, DateTime expires)
private void RemoveUserTokenForRedis(String userId, String accessToken)
private IEnumerable<String> GetUserAccessTokensForRedis(String userId)
private void RemoveAllUserTokensForRedis(String userId)
```

### 3. Memory 模式实现

#### 特点
- **信号量保护**：使用用户级别的 `SemaphoreSlim` 确保并发安全
- **内存优化**：自动清理未使用的信号量，避免内存泄漏
- **轻量级锁**：避免不同用户间的锁竞争

#### 核心方法
```csharp
private void AddUserTokenForMemory(String userId, String accessToken, DateTime expires)
private void RemoveUserTokenForMemory(String userId, String accessToken)
private IEnumerable<String> GetUserAccessTokensForMemory(String userId)
private void RemoveAllUserTokensForMemory(String userId)
```

### 4. 自动关联机制

在 `SaveToken` 方法中自动建立用户与 Token 的关联：
```csharp
public void SaveToken(JsonWebToken token, DateTime expires)
{
    _cache.Set(GetTokenKey(token.AccessToken), token, expires.Subtract(DateTime.UtcNow));
    _cache.Set(GetBindRefreshTokenKey(token.RefreshToken), token, expires.Subtract(DateTime.UtcNow));
    
    // 添加用户Token关联
    if (token.UId > 0)
    {
        AddUserToken(token.UId.ToString(), token.AccessToken, expires);
    }
}
```

## 技术优势

### Redis 模式优势
1. **天然线程安全**：Redis 的原子操作确保并发安全
2. **高性能**：无需应用层锁机制，减少性能开销
3. **分布式支持**：支持多实例间的 Token 管理
4. **简化代码**：去除复杂的锁管理逻辑

### Memory 模式优势
1. **轻量级锁**：使用 `SemaphoreSlim` 比 `lock` 更轻量
2. **用户级隔离**：不同用户的 Token 操作互不影响
3. **内存优化**：自动清理未使用的信号量
4. **向后兼容**：保持原有功能完整性

## 使用说明

### 自动模式切换
系统会根据缓存类型自动选择实现方式：
- 当 `_cache.Name` 为 "RedisCache" 时，使用 Redis 模式
- 其他情况使用 Memory 模式

### 缓存键结构
```
jwt:user:tokens:{userId}    # 用户Token列表
jwt:token:access:{token}    # AccessToken信息  
jwt:token:refresh:{token}   # RefreshToken信息
jwt:token:bind:{token}      # RefreshToken绑定
```

## 兼容性保证

- ✅ **完全向后兼容**：现有代码无需修改
- ✅ **接口保持不变**：所有公共方法签名保持原样
- ✅ **功能完整**：所有原有功能得到保留
- ✅ **渐进式采用**：可以选择性使用新功能

## 性能提升

### Redis 环境
- **并发性能**：去除应用层锁，提升并发处理能力
- **分布式能力**：支持多服务实例间的 Token 一致性管理
- **原子操作**：利用 Redis 原生 Set 操作的原子性

### Memory 环境  
- **锁粒度优化**：用户级别隔离，减少锁竞争
- **内存管理**：自动清理机制，避免内存泄漏
- **响应速度**：本地缓存的快速访问特性

这次改进成功实现了 Redis 和内存缓存的差异化处理，在保持向后兼容的同时，为不同环境提供了最优的性能方案。
