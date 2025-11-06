export interface Token {
  token: string;
  expires_at: number;
  created_at: number;
}

export interface TokenResponse {
  token: string;
  expires_at: number;
}

export interface TokensResponse {
  tokens: Token[];
  count: number;
}

export interface HealthResponse {
  status: string;
  uptime: number;
  active_tokens?: number;
  cached_clients?: number;
}

export interface Config {
  port: number;
  default_ttl: number;
  host_allowlist: string[];
  direct_hosts: string[];
}
