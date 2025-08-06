# Node-Unblocker Proxy Design Document

## 1. 项目定位

这是一个 **Toy Project**，基于 `node-unblocker` 库实现的个人用前缀 URL 代理，用于在 ChatGPT Agent 中通过自定义 Token 安全访问校园或机构付费学术资源。

## 2. 总体架构

```
ChatGPT Agent 请求 → Node.js HTTP Server + node-unblocker 代理
  ├─ 配置验证（启动时）
  ├─ 多用户 Token 验证
  ├─ URL 无转义解析
  ├─ 域名允许列表
  └─ PDF/大文件直通
→ 目标出版商网站
```

**注**：项目不包含外部隧道或 Load Balancer，仅供本地或私有服务器部署。

## 3. 组件一览

- **node-unblocker**：核心代理和内容重写库
- **http (Node.js 内置)**：原生 HTTP 服务器，更轻量级
- **crypto (Node.js 内置)**：生成随机 Token
- **config.json**：配置管理，存放 `admin_token`、TTL、允许列表等

## 4. 快速部署

### 4.1 准备环境

```bash
mkdir webpage-reverse-proxy
cd webpage-reverse-proxy
pnpm init
pnpm install unblocker morgan
```

### 4.2 配置文件 `config.json`

```json
{
  "admin_token": ["<YOUR_ADMIN_TOKEN_1>", "<YOUR_ADMIN_TOKEN_2>"],
  "port": 8080,
  "default_ttl": 7200,
  "domain_allowlist_url": "https://gitlab.com/-/snippets/3623446/raw/main/domains.txt?inline=false",
  "host_allowlist": ["*.acm.org","*.springer.com","*.ieee.org"],
  "direct_hosts": ["cdn.springer.com","static.ieee.org"]
}
```

**配置说明**：
- `domain_allowlist_url`: 可选项，指向远程域名列表文件的 URL
- 远程列表中以点开头的域名（如 `.nature.com`）会自动转换为通配符格式（`*.nature.com`）
- 本地 `host_allowlist` 与远程列表会合并使用

### 4.3 核心脚本 `proxy.js`

```js
const http = require('http');
const https = require('https');
const url = require('url');
const fs = require('fs');
const crypto = require('crypto');
const Unblocker = require('unblocker');

// 加载和验证配置
let cfg;
try {
  if (!fs.existsSync('config.json')) {
    console.error('ERROR: config.json not found');
    process.exit(1);
  }
  cfg = JSON.parse(fs.readFileSync('config.json', 'utf8'));
} catch (error) {
  console.error('ERROR: Failed to load config.json:', error.message);
  process.exit(1);
}

// 验证必要配置
if (!cfg.admin_token || !Array.isArray(cfg.admin_token) || cfg.admin_token.length === 0) {
  console.error('ERROR: Invalid config.json format - admin_token must be a non-empty array');
  process.exit(1);
}

// 初始化 host_allowlist
if (!cfg.host_allowlist || !Array.isArray(cfg.host_allowlist)) {
  cfg.host_allowlist = [];
}

// 下载并解析域名允许列表
async function loadDomainAllowlist() {
  if (cfg.domain_allowlist_url) {
    try {
      console.log('Loading domain allowlist from:', cfg.domain_allowlist_url);
      const domains = await fetchDomainList(cfg.domain_allowlist_url);
      // 将以点开头的域名转换为通配符格式
      domains.forEach(domain => {
        if (domain.startsWith('.')) {
          const wildcardDomain = '*' + domain;
          if (!cfg.host_allowlist.includes(wildcardDomain)) {
            cfg.host_allowlist.push(wildcardDomain);
          }
        } else if (!cfg.host_allowlist.includes(domain)) {
          cfg.host_allowlist.push(domain);
        }
      });
      console.log(`Added ${domains.length} domains to allowlist`);
    } catch (error) {
      console.warn('Failed to load domain allowlist:', error.message);
    }
  }
}

// 获取域名列表的函数
function fetchDomainList(domainUrl) {
  return new Promise((resolve, reject) => {
    https.get(domainUrl, (res) => {
      if (res.statusCode !== 200) {
        reject(new Error(`HTTP ${res.statusCode}`));
        return;
      }
      
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        const domains = data.split('\n')
          .map(line => line.trim())
          .filter(line => line && !line.startsWith('#'))
          .filter(line => line.startsWith('.') || !line.includes(' '));
        resolve(domains);
      });
    }).on('error', reject);
  });
}

// 多用户 Token 管理
const userTokens = new Map(); // { token: { expiry: timestamp } }

// 清理过期 Token
setInterval(() => {
  const now = Date.now();
  for (const [token, data] of userTokens.entries()) {
    if (now > data.expiry) {
      userTokens.delete(token);
    }
  }
}, 60000); // 每分钟清理一次

// 创建 unblocker 实例
const unblocker = Unblocker({
  prefix: '/',
  hostWhitelist: cfg.host_allowlist,
  directHosts: cfg.direct_hosts || []
});

// 创建服务器
const server = http.createServer((req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;
  
  console.log(`${new Date().toISOString()} ${req.method} ${pathname}`);
  
  // 管理接口：生成 Token
  if (pathname === '/admin/token') {
    const adminToken = req.headers['x-admin-token'] || parsedUrl.query.admin_token;
    if (!cfg.admin_token.includes(adminToken)) {
      res.writeHead(401, {'Content-Type': 'application/json'});
      return res.end('{"error":"Unauthorized"}');
    }
    
    const ttl = parseInt(parsedUrl.query.expires_after) || cfg.default_ttl;
    const token = crypto.randomBytes(16).toString('hex');
    const expiry = Date.now() + ttl * 1000;
    
    userTokens.set(token, { expiry });
    
    res.writeHead(200, {'Content-Type': 'application/json'});
    return res.end(JSON.stringify({ token, expires_in: ttl }));
  }
  
  // 代理请求：支持不转义的完整 URL
  // 路径格式: /<token>/fetch/<完整URL>
  const match = pathname.match(/^\/([^\/]+)\/fetch\/(.+)$/);
  if (match) {
    const [, token, targetUrl] = match;
    
    // Token 验证
    if (!cfg.admin_token.includes(token) && 
        (!userTokens.has(token) || Date.now() > userTokens.get(token).expiry)) {
      res.writeHead(403, {'Content-Type': 'text/plain'});
      return res.end('Forbidden');
    }
    
    // 重构请求 URL，让 unblocker 处理
    // 如果目标URL不以http开头，自动添加https://
    let fullUrl = targetUrl;
    if (!fullUrl.startsWith('http://') && !fullUrl.startsWith('https://')) {
      fullUrl = 'https://' + fullUrl;
    }
    
    req.url = '/' + fullUrl;
    return unblocker(req, res);
  }
  
  // 其他请求直接用 unblocker 处理
  unblocker(req, res);
});

// 启动服务器
const PORT = cfg.port || process.env.PORT || 8080;

async function startServer() {
  // 先加载域名允许列表
  await loadDomainAllowlist();
  
  server.listen(PORT, () => {
    console.log(`Proxy server running on port ${PORT}`);
    console.log(`Admin token: ${cfg.admin_token.join(', ')}`);
    console.log(`Allowed hosts: ${cfg.host_allowlist.length} patterns`);
  });
}

startServer().catch(error => {
  console.error('Failed to start server:', error);
  process.exit(1);
});
```

## 5. 使用方式

### 5.1 动态域名列表

代理启动时会自动从配置的 `domain_allowlist_url` 下载域名列表：
- 支持以点开头的域名格式（如 `.nature.com`），自动转换为通配符格式（`*.nature.com`）
- 与本地配置的 `host_allowlist` 合并使用
- 下载失败时会继续使用本地配置

**示例域名文件格式**：
```
.12345fund.com
.18thcjournals.amdigital.co.uk 
.aac.amdigital.co.uk 
.aacr.org 
.aap.amdigital.co.uk 
.academic.eb.cnpeak.com 
.academic.eb.com 
.academic.oup.com
```

### 5.2 API 使用

1. **获取 Token**：
   ```bash
   curl "http://your-server:8080/admin/token?admin_token=<ONE_OF_YOUR_ADMIN_TOKENS>&expires_after=3600"
   ```
2. **在 ChatGPT 提示词中**：
   ```text
   Fetch via proxy: http://your-server:8080/<TOKEN>/fetch/https://dl.acm.org/doi/10.1145/example
   ```
   - 直接使用原始 URL，无需进行转义
   - 支持 `https://domain.com/path` 和 `domain.com/path` 两种格式
   - 后者会自动添加 `https://` 前缀

## 6. 简易日志

代理启动后，控制台实时输出请求日志（时间戳、方法、路径），以及任何错误信息。Token 会自动清理过期项，无需外部监控。

---

*版本：1.0 (Toy Project)*

