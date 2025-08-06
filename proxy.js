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
    console.error('Please copy config.example.json to config.json and configure it');
    process.exit(1);
  }
  cfg = JSON.parse(fs.readFileSync('config.json', 'utf8'));
} catch (error) {
  console.error('ERROR: Failed to load config.json:', error.message);
  process.exit(1);
}

// 验证必要配置
if (!cfg.admin_token || !Array.isArray(cfg.admin_token) || cfg.admin_token.length === 0) {
  console.error('ERROR: Invalid config.json format');
  console.error('Required fields: admin_token (must be a non-empty array)');
  process.exit(1);
}

// 初始化 host_allowlist
if (!cfg.host_allowlist || !Array.isArray(cfg.host_allowlist)) {
  cfg.host_allowlist = [];
}

// 安全检查：确保管理员token不是默认值
if (cfg.admin_token.includes('your-secure-admin-token-here') || 
    cfg.admin_token.includes('your-secure-admin-token-1-here') ||
    cfg.admin_token.includes('your-secure-admin-token-2-here')) {
  console.error('ERROR: Please change the admin_token in config.json from the default values');
  process.exit(1);
}

// 下载并解析域名允许列表
async function loadDomainAllowlist() {
  if (cfg.domain_allowlist_url) {
    try {
      console.log('Loading domain allowlist from:', cfg.domain_allowlist_url);
      const domains = await fetchDomainList(cfg.domain_allowlist_url);
      // 将以点开头的域名转换为通配符格式，并添加到 host_allowlist
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
      console.log(`Added ${domains.length} domains to allowlist. Total: ${cfg.host_allowlist.length}`);
    } catch (error) {
      console.warn('Failed to load domain allowlist:', error.message);
      console.log('Continuing with config-only allowlist');
    }
  }
}

// 获取域名列表的函数
function fetchDomainList(domainUrl) {
  return new Promise((resolve, reject) => {
    https.get(domainUrl, (res) => {
      if (res.statusCode !== 200) {
        reject(new Error(`HTTP ${res.statusCode}: ${res.statusMessage}`));
        return;
      }
      
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const domains = data.split('\n')
            .map(line => line.trim())
            .filter(line => line && !line.startsWith('#'))
            .filter(line => line.startsWith('.') || !line.includes(' '));
          resolve(domains);
        } catch (error) {
          reject(error);
        }
      });
    }).on('error', reject);
  });
}

// 多用户 Token 管理
const userTokens = new Map(); // { token: { expiry: timestamp } }

// 清理过期 Token
setInterval(() => {
  const now = Date.now();
  let cleanedCount = 0;
  for (const [token, data] of userTokens.entries()) {
    if (now > data.expiry) {
      userTokens.delete(token);
      cleanedCount++;
    }
  }
  if (cleanedCount > 0) {
    console.log(`Cleaned ${cleanedCount} expired tokens`);
  }
}, 60000); // 每分钟清理一次

// 域名匹配函数
function isHostAllowed(hostname, allowlist) {
  for (const pattern of allowlist) {
    if (pattern.startsWith('*.')) {
      const domain = pattern.substring(2);
      if (hostname === domain || hostname.endsWith('.' + domain)) {
        return true;
      }
    } else if (hostname === pattern) {
      return true;
    }
  }
  return false;
}

// 创建服务器
const server = http.createServer((req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;
  
  console.log(`${new Date().toISOString()} ${req.method} ${pathname} - ${req.headers['user-agent'] || 'Unknown'}`);
  
  // 健康检查接口
  if (pathname === '/health') {
    res.writeHead(200, {'Content-Type': 'application/json'});
    return res.end(JSON.stringify({ 
      status: 'ok', 
      active_tokens: userTokens.size,
      uptime: process.uptime()
    }));
  }
  
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
    
    console.log(`Generated token: ${token} (expires in ${ttl}s)`);
    
    res.writeHead(200, {'Content-Type': 'application/json'});
    return res.end(JSON.stringify({ 
      token, 
      expires_in: ttl,
      expires_at: new Date(expiry).toISOString()
    }));
  }
  
  // 管理接口：列出活跃Token
  if (pathname === '/admin/tokens') {
    const adminToken = req.headers['x-admin-token'] || parsedUrl.query.admin_token;
    if (!cfg.admin_token.includes(adminToken)) {
      res.writeHead(401, {'Content-Type': 'application/json'});
      return res.end('{"error":"Unauthorized"}');
    }
    
    const tokens = [];
    const now = Date.now();
    for (const [token, data] of userTokens.entries()) {
      tokens.push({
        token: token.substring(0, 8) + '...',
        expires_in: Math.max(0, Math.floor((data.expiry - now) / 1000)),
        expires_at: new Date(data.expiry).toISOString()
      });
    }
    
    res.writeHead(200, {'Content-Type': 'application/json'});
    return res.end(JSON.stringify({ tokens, count: tokens.length }));
  }
  
  // 代理请求：支持不转义的完整 URL
  // 路径格式: /<token>/fetch/<完整URL>
  // 或者是unblocker重写后的路径: /<token>/fetch/https/example.com/path
  const match = pathname.match(/^\/([^\/]+)\/fetch\/(.+)$/);
  if (match) {
    const [, token, targetUrl] = match;
    
    // Token 验证
    const now = Date.now();
    if (!cfg.admin_token.includes(token) && 
        (!userTokens.has(token) || now > userTokens.get(token).expiry)) {
      res.writeHead(403, {'Content-Type': 'text/plain'});
      return res.end('Forbidden: Invalid or expired token');
    }
    
    // 为本次请求动态创建unblocker实例，确保后续链接都带有正确的token
    const unblocker = Unblocker({
      prefix: `/${token}/fetch/`,
      responseMiddleware: [
        (data) => {
          if (data.headers) {
            data.headers['access-control-allow-origin'] = '*';
          }
        }
      ]
    });
    
    // 检查目标URL是否在允许列表中
    // 注意：unblocker会处理URL的解析，我们只需要在初次请求时校验
    // 简单的判断，如果targetUrl看起来像一个域名，就校验它
    if (!targetUrl.startsWith('http')) {
        // 这是一个由unblocker重写后的内部路径，我们信任它，直接代理
        return unblocker(req, res);
    }

    try {
      const targetHost = new URL(targetUrl).hostname;
      if (!isHostAllowed(targetHost, cfg.host_allowlist)) {
        console.warn(`Redirecting unauthorized host to original URL: ${targetHost} -> ${targetUrl}`);
        res.writeHead(302, {
          'Location': targetUrl,
          'Content-Type': 'text/plain'
        });
        return res.end(`Redirecting to: ${targetUrl}`);
      }
      
      console.log(`Proxying initial request to: ${targetUrl}`);
      return unblocker(req, res);

    } catch (urlError) {
      console.error(`Invalid URL: ${targetUrl}`, urlError.message);
      res.writeHead(400, {'Content-Type': 'text/plain'});
      return res.end('Bad Request: Invalid URL');
    }
  }
  
  // 根路径显示使用说明
  if (pathname === '/') {
    res.writeHead(200, {'Content-Type': 'text/html; charset=utf-8'});
    return res.end(`
<!DOCTYPE html>
<html>
<head>
    <title>Webpage Reverse Proxy</title>
    <meta charset="utf-8">
    <style>
        body { font-family: monospace; margin: 40px; line-height: 1.6; }
        .endpoint { background: #f5f5f5; padding: 10px; margin: 10px 0; border-radius: 4px; }
        .method { color: #007acc; font-weight: bold; }
        .example { background: #e8f4fd; padding: 15px; margin: 15px 0; border-radius: 4px; border-left: 4px solid #007acc; }
    </style>
</head>
<body>
    <h1>Webpage Reverse Proxy</h1>
    <p>Status: <strong>Running</strong></p>
    <p>Active tokens: <strong>${userTokens.size}</strong></p>
    
    <h2>API Endpoints</h2>
    
    <div class="endpoint">
        <div class="method">GET</div>
        <div>/health</div>
        <div>Health check and server status</div>
    </div>
    
    <div class="endpoint">
        <div class="method">GET</div>
        <div>/admin/token?admin_token=&lt;ADMIN_TOKEN&gt;&expires_after=&lt;SECONDS&gt;</div>
        <div>Generate a new access token</div>
    </div>
    
    <div class="endpoint">
        <div class="method">GET</div>
        <div>/admin/tokens?admin_token=&lt;ADMIN_TOKEN&gt;</div>
        <div>List active tokens</div>
    </div>
    
    <div class="endpoint">
        <div class="method">GET</div>
        <div>/&lt;TOKEN&gt;/fetch/&lt;URL&gt;</div>
        <div>Proxy request to target URL</div>
    </div>
    
    <h2>Usage Examples</h2>
    
    <div class="example">
        <strong>1. Generate a token:</strong><br>
        <code>curl "http://localhost:${cfg.port}/admin/token?admin_token=${cfg.admin_token[0]}&expires_after=3600"</code>
    </div>
    
    <div class="example">
        <strong>2. Use token to fetch content:</strong><br>
        <code>curl "http://localhost:${cfg.port}/&lt;TOKEN&gt;/fetch/https://www.nature.com/articles/example"</code><br>
        <code>curl "http://localhost:${cfg.port}/&lt;TOKEN&gt;/fetch/dl.acm.org/doi/10.1145/example"</code> (auto-adds https://)
    </div>
    
    <div class="example">
        <strong>3. For ChatGPT usage:</strong><br>
        <em>Please fetch via proxy: http://localhost:${cfg.port}/&lt;TOKEN&gt;/fetch/https://example.com/path</em>
    </div>
    
    <h2>Configuration</h2>
    <p><strong>Allowed hosts:</strong> ${cfg.host_allowlist.join(', ')}</p>
    <p><strong>Default TTL:</strong> ${cfg.default_ttl} seconds</p>
    <p><strong>Direct hosts:</strong> ${(cfg.direct_hosts || []).join(', ') || 'None'}</p>
</body>
</html>
    `);
  }
  
  // 其他路径返回404
  res.writeHead(404, {'Content-Type': 'text/plain'});
  res.end('Not Found');
});

// 错误处理
server.on('error', (err) => {
  console.error('Server error:', err);
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

// 优雅关闭
process.on('SIGINT', () => {
  console.log('\nReceived SIGINT, shutting down gracefully...');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});

// 启动服务器
const PORT = cfg.port || process.env.PORT || 8080;
const HOST = process.env.HOST || '0.0.0.0';

async function startServer() {
  // 先加载域名允许列表
  await loadDomainAllowlist();

  server.listen(PORT, HOST, () => {
    console.log(`🚀 Proxy server running on http://${HOST}:${PORT}`);
    console.log(`📋 Admin tokens: ${cfg.admin_token.join(', ')}`);
    console.log(`⏰ Default token TTL: ${cfg.default_ttl}s`);
    console.log(`🛡️  Allowed hosts: ${cfg.host_allowlist.length} patterns`);
    console.log(`📊 Health check: http://${HOST}:${PORT}/health`);
    console.log(`📝 Web UI: http://${HOST}:${PORT}/`);
    if (cfg.domain_allowlist_url) {
      console.log(`🌐 Domain list URL: ${cfg.domain_allowlist_url}`);
    }
    console.log('');
    console.log('Press Ctrl+C to stop the server');
  });
}

startServer().catch(error => {
  console.error('Failed to start server:', error);
  process.exit(1);
});
