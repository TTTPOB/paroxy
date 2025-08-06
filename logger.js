const util = require('util');

// ANSI color codes
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  gray: '\x1b[90m'
};

// Log levels
const LOG_LEVELS = {
  ERROR: 0,
  WARN: 1,
  INFO: 2,
  DEBUG: 3,
  TRACE: 4
};

class Logger {
  constructor(level = 'INFO') {
    this.level = LOG_LEVELS[level.toUpperCase()] ?? LOG_LEVELS.INFO;
  }

  setLevel(level) {
    this.level = LOG_LEVELS[level.toUpperCase()] ?? LOG_LEVELS.INFO;
  }

  _log(level, levelName, color, ...args) {
    if (level > this.level) return;
    
    const timestamp = new Date().toISOString();
    const prefix = `${colors.gray}${timestamp}${colors.reset} ${color}${levelName}${colors.reset}`;
    
    // Format arguments
    const formattedArgs = args.map(arg => {
      if (typeof arg === 'object' && arg !== null) {
        return util.inspect(arg, { colors: true, depth: 3 });
      }
      return arg;
    });
    
    console.log(prefix, ...formattedArgs);
  }

  error(...args) {
    this._log(LOG_LEVELS.ERROR, '❌ ERROR', colors.red, ...args);
  }

  warn(...args) {
    this._log(LOG_LEVELS.WARN, '⚠️  WARN ', colors.yellow, ...args);
  }

  info(...args) {
    this._log(LOG_LEVELS.INFO, '💡 INFO ', colors.cyan, ...args);
  }

  success(...args) {
    this._log(LOG_LEVELS.INFO, '✅ SUCC ', colors.green, ...args);
  }

  debug(...args) {
    this._log(LOG_LEVELS.DEBUG, '🔍 DEBUG', colors.magenta, ...args);
  }

  trace(...args) {
    this._log(LOG_LEVELS.TRACE, '🔎 TRACE', colors.gray, ...args);
  }

  // HTTP request logging with custom formatting
  request(method, path, userAgent, status = null) {
    const statusColor = status ? (status >= 400 ? colors.red : status >= 300 ? colors.yellow : colors.green) : '';
    const statusText = status ? `${statusColor}${status}${colors.reset} ` : '';
    
    this._log(
      LOG_LEVELS.INFO, 
      '🌐 HTTP ', 
      colors.blue,
      `${colors.bright}${method}${colors.reset} ${path} ${statusText}${colors.dim}- ${userAgent}${colors.reset}`
    );
  }

  // Server events
  server(...args) {
    this._log(LOG_LEVELS.INFO, '🚀 SERV ', colors.green, ...args);
  }

  // Security events
  security(...args) {
    this._log(LOG_LEVELS.WARN, '🛡️  SEC ', colors.red, ...args);
  }

  // Token management
  token(...args) {
    this._log(LOG_LEVELS.INFO, '🔑 TOKEN', colors.magenta, ...args);
  }

  // Proxy events
  proxy(...args) {
    this._log(LOG_LEVELS.INFO, '🔄 PROXY', colors.cyan, ...args);
  }
}

// Create default logger instance
const logger = new Logger(process.env.LOG_LEVEL || 'INFO');

module.exports = logger;
