# Webpage Reverse Proxy

基于 node-unblocker 的学术资源反向代理服务器，用于在 ChatGPT Agent 中安全访问校园或机构付费学术资源。

## 快速开始

### 1. 安装依赖
```bash
pnpm install
# 或者
pnpm install
```

### 2. 配置服务
```bash
# 复制配置示例文件
cp config.example.json config.json

# 编辑配置文件，修改 admin_token 等设置
```

### 3. 启动服务
```bash
pnpm start
```

服务器将在 `http://localhost:8080` 启动。

## 配置说明

`config.json` 文件包含以下配置选项：

- `admin_token`: 管理员访问令牌（必须修改默认值）
- `port`: 服务器端口（默认 8080）
- `default_ttl`: 默认令牌有效时间（秒）
- `host_allowlist`: 允许访问的域名列表（支持通配符 `*.domain.com`）
- `direct_hosts`: 直接访问的静态资源域名

## API 接口

### 健康检查
```
GET /health
```

### 管理界面
```
GET /admin?admin_token=<ADMIN_TOKEN>
```
提供网页界面，可以通过浏览器生成令牌和复制提示词模板。

### 生成访问令牌
```
GET /admin/token?admin_token=<ADMIN_TOKEN>&expires_after=<SECONDS>
```

### 查看活跃令牌
```
GET /admin/tokens?admin_token=<ADMIN_TOKEN>
```

### 代理访问
```
GET /<TOKEN>/fetch/<TARGET_URL>
```

## 使用示例

1. **生成令牌**：
   ```bash
   curl "http://localhost:8080/admin/token?admin_token=your-admin-token&expires_after=3600"
   ```

2. **访问学术资源**：
   ```bash
   curl "http://localhost:8080/<TOKEN>/fetch/https://dl.acm.org/doi/10.1145/example"
   ```

3. **暴露到公网**:
   可考虑使用cloudflare tunnel等工具。

4. **使用管理界面**：
   访问 `http://localhost:8080/admin?admin_token=<你的管理员令牌>` 打开网页管理界面，可以：
   - 生成新的访问令牌
   - 查看活跃令牌列表
   - 生成和复制提示词模板

5. **在 ChatGPT 中使用**：
   使用管理界面生成的提示词模板，或手动添加：
   ```
   需要访问学术文章时请使用这个代理: http://<exposed-service-url>/<TOKEN>/fetch/${orignal_article_url}
   ```

## 安全特性

- ✅ 基于令牌的访问控制
- ✅ 域名白名单限制
- ✅ 令牌自动过期清理
- ✅ 管理员令牌验证
- ✅ 请求日志记录

## 注意事项

- 这是一个 **Toy Project**，仅供学习和个人使用
- 请确保遵守目标网站的使用条款
- 建议在私有网络环境中部署
- 定期更新依赖包以确保安全性

## 故障排除

### 查看日志

服务器启动后会在控制台显示：
- 请求日志（时间戳、方法、路径、User-Agent）
- 令牌生成和清理信息
- 错误和警告信息

## 开发

### 项目结构
```
├── proxy.js           # 主服务器文件
├── package.json       # 项目配置
├── config.json        # 服务器配置（需要创建）
├── config.example.json # 配置示例
└── README.md          # 说明文档
```

### 扩展功能

可以根据需要添加：
- 用户认证系统
- 访问日志持久化
- 缓存机制
- 负载均衡
- HTTPS 支持

## 许可证

MIT License


## Note
design doc是早期vibe coding留着的，放在仓库里仅供参考，与实际的实现不完全一致。