const http = require('http');
const https = require('https');
const url = require('url');
const fs = require('fs');
const crypto = require('crypto');
const Unblocker = require('unblocker');
const logger = require('./logger');

// 加载和验证配置
let cfg;
try {
  if (!fs.existsSync('config.json')) {
    logger.error('config.json not found');
    logger.error('Please copy config.example.json to config.json and configure it');
    process.exit(1);
  }
  cfg = JSON.parse(fs.readFileSync('config.json', 'utf8'));
} catch (error) {
  logger.error('Failed to load config.json:', error.message);
  process.exit(1);
}

// 验证必要配置
if (!cfg.admin_token || !Array.isArray(cfg.admin_token) || cfg.admin_token.length === 0) {
  logger.error('Invalid config.json format');
  logger.error('Required fields: admin_token (must be a non-empty array)');
  process.exit(1);
}

// 验证至少有一个域名允许列表源
const hasHostAllowlist = cfg.host_allowlist && Array.isArray(cfg.host_allowlist) && cfg.host_allowlist.length > 0;
const hasDomainAllowlistUrl = cfg.domain_allowlist_url && typeof cfg.domain_allowlist_url === 'string' && cfg.domain_allowlist_url.trim() !== '';

if (!hasHostAllowlist && !hasDomainAllowlistUrl) {
  logger.error('Invalid config.json format');
  logger.error('At least one of the following must be configured:');
  logger.error('- host_allowlist: non-empty array of allowed domains/patterns');
  logger.error('- domain_allowlist_url: valid URL to fetch domain list from');
  process.exit(1);
}

// 初始化 host_allowlist
if (!cfg.host_allowlist || !Array.isArray(cfg.host_allowlist)) {
  cfg.host_allowlist = [];
}

// 配置日志级别
if (cfg.log_level) {
  logger.setLevel(cfg.log_level);
  logger.debug(`Log level set to: ${cfg.log_level}`);
}

// 安全检查：确保管理员token不是默认值
if (cfg.admin_token.includes('your-secure-admin-token-here') || 
    cfg.admin_token.includes('your-secure-admin-token-1-here') ||
    cfg.admin_token.includes('your-secure-admin-token-2-here')) {
  logger.error('Please change the admin_token in config.json from the default values');
  process.exit(1);
}

// 下载并解析域名允许列表
async function loadDomainAllowlist() {
  if (cfg.domain_allowlist_url) {
    try {
      logger.info('Loading domain allowlist from:', cfg.domain_allowlist_url);
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
      logger.success(`Added ${domains.length} domains to allowlist. Total: ${cfg.host_allowlist.length}`);
    } catch (error) {
      logger.warn('Failed to load domain allowlist:', error.message);
      logger.info('Continuing with config-only allowlist');
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

// Unblocker 客户端缓存
const unblockerClients = new Map(); // { token: unblockerInstance }

// 清理过期 Token 和对应的客户端
setInterval(() => {
  const now = Date.now();
  let cleanedCount = 0;
  for (const [token, data] of userTokens.entries()) {
    if (now > data.expiry) {
      userTokens.delete(token);
      // 同时清理对应的unblocker客户端
      if (unblockerClients.has(token)) {
        unblockerClients.delete(token);
      }
      cleanedCount++;
    }
  }
  if (cleanedCount > 0) {
    logger.token(`Cleaned ${cleanedCount} expired tokens and clients`);
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

// 获取或创建 unblocker 客户端
function getUnblockerClient(token) {
  if (!unblockerClients.has(token)) {
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
    unblockerClients.set(token, unblocker);
    logger.debug(`Created new unblocker client for token: ${token.substring(0, 8)}...`);
  }
  return unblockerClients.get(token);
}

// 创建服务器
const server = http.createServer((req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;
  
  logger.request(req.method, pathname, req.headers['user-agent'] || 'Unknown');
  
  // 健康检查接口
  if (pathname === '/health') {
    res.writeHead(200, {'Content-Type': 'application/json'});
    return res.end(JSON.stringify({
      status: 'ok',
      active_tokens: userTokens.size,
      cached_clients: unblockerClients.size,
      uptime: process.uptime()
    }));
  }
  
  // 管理界面路由 - 需要admin token认证
  if (pathname === '/admin' || pathname === '/admin/') {
    const adminToken = req.headers['x-admin-token'] || parsedUrl.query.admin_token;
    
    // 如果没有提供admin token，显示登录页面
    if (!adminToken) {
      try {
        const adminHtml = fs.readFileSync('./public/admin.html', 'utf8');
        res.writeHead(200, {'Content-Type': 'text/html; charset=utf-8'});
        return res.end(adminHtml);
      } catch (error) {
        logger.error('Failed to read admin.html:', error.message);
        res.writeHead(500, {'Content-Type': 'text/plain'});
        return res.end('Internal Server Error');
      }
    }
    
    // 验证admin token
    if (!cfg.admin_token.includes(adminToken)) {
      res.writeHead(401, {'Content-Type': 'text/html; charset=utf-8'});
      return res.end(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>访问被拒绝</title>
          <meta charset="utf-8">
          <style>
            body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
            .error { color: #d32f2f; background: #ffebee; padding: 20px; border-radius: 5px; }
            a { color: #1976d2; }
          </style>
        </head>
        <body>
          <div class="error">
            <h1>访问被拒绝</h1>
            <p>提供的管理员令牌无效。</p>
            <p><a href="/admin">返回登录页面</a></p>
          </div>
        </body>
        </html>
      `);
    }
    
    // 如果admin token有效，显示管理界面
    try {
      let adminHtml = fs.readFileSync('./public/admin.html', 'utf8');
      // 在HTML中注入admin token，这样前端就不需要再次输入
      adminHtml = adminHtml.replace(
        '<script>',
        `<script>
          window.adminToken = '${adminToken}';
          window.serverUrl = 'http://localhost:${cfg.port}';
        `
      );
      res.writeHead(200, {'Content-Type': 'text/html; charset=utf-8'});
      return res.end(adminHtml);
    } catch (error) {
      logger.error('Failed to read admin.html:', error.message);
      res.writeHead(500, {'Content-Type': 'text/plain'});
      return res.end('Internal Server Error');
    }
  }
  
  // 管理接口：生成 Token
  if (pathname === '/admin/token') {
    const adminToken = req.headers['x-admin-token'] || parsedUrl.query.admin_token;
    if (!cfg.admin_token.includes(adminToken)) {
      res.writeHead(401, {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization'
      });
      return res.end('{"error":"Unauthorized"}');
    }
    
    const ttl = parseInt(parsedUrl.query.expires_after) || cfg.default_ttl;
    const token = crypto.randomBytes(16).toString('hex');
    const expiry = Date.now() + ttl * 1000;
    
    userTokens.set(token, { expiry });
    
    logger.token(`Generated token: ${token} (expires in ${ttl}s)`);
    
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    });
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
      res.writeHead(401, {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization'
      });
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
    
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    });
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
    
    // 获取或创建该token对应的unblocker客户端
    const unblocker = getUnblockerClient(token);
    
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
        logger.security(`Redirecting unauthorized host: ${targetHost} -> ${targetUrl}`);
        res.writeHead(302, {
          'Location': targetUrl,
          'Content-Type': 'text/plain'
        });
        return res.end(`Redirecting to: ${targetUrl}`);
      }
      
      logger.proxy(`Proxying initial request to: ${targetUrl}`);
      return unblocker(req, res);

    } catch (urlError) {
      logger.error(`Invalid URL: ${targetUrl}`, urlError.message);
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
    <p>Cached clients: <strong>${unblockerClients.size}</strong></p>
    
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
  logger.error('Server error:', err);
});

process.on('uncaughtException', (err) => {
  logger.error('Uncaught Exception:', err);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

// 优雅关闭
process.on('SIGINT', () => {
  logger.info('Received SIGINT, shutting down gracefully...');
  server.close(() => {
    logger.info('Server closed');
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
    logger.server(`Proxy server running on http://${HOST}:${PORT}`);
    logger.server(`Admin tokens: ${cfg.admin_token.join(', ')}`);
    logger.server(`Default token TTL: ${cfg.default_ttl}s`);
    logger.server(`Allowed hosts: ${cfg.host_allowlist.length} patterns`);
    logger.server(`Health check: http://${HOST}:${PORT}/health`);
    logger.server(`Web UI: http://${HOST}:${PORT}/`);
    if (cfg.domain_allowlist_url) {
      logger.server(`Domain list URL: ${cfg.domain_allowlist_url}`);
    }
    logger.info('Press Ctrl+C to stop the server');
  });
}

startServer().catch(error => {
  logger.error('Failed to start server:', error);
  process.exit(1);
});
