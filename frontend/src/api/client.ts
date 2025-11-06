import type { TokenResponse, Token, HealthResponse, TokensResponse } from '../types';

const BASE_URL = '';

export class ApiClient {
  private adminToken: string;

  constructor(adminToken: string) {
    this.adminToken = adminToken;
  }

  async generateToken(expiresAfter?: number): Promise<TokenResponse> {
    const params = new URLSearchParams({
      admin_token: this.adminToken,
      ...(expiresAfter && { expires_after: expiresAfter.toString() }),
    });

    const response = await fetch(`${BASE_URL}/admin/token?${params}`);
    if (!response.ok) {
      throw new Error(`Failed to generate token: ${response.statusText}`);
    }
    return response.json();
  }

  async getTokens(): Promise<Token[]> {
    const params = new URLSearchParams({
      admin_token: this.adminToken,
    });

    const response = await fetch(`${BASE_URL}/admin/tokens?${params}`);
    if (!response.ok) {
      throw new Error(`Failed to fetch tokens: ${response.statusText}`);
    }
    const data: TokensResponse = await response.json();
    return data.tokens;
  }

  async getHealth(): Promise<HealthResponse> {
    const response = await fetch(`${BASE_URL}/health`);
    if (!response.ok) {
      throw new Error(`Failed to fetch health: ${response.statusText}`);
    }
    return response.json();
  }

  generateProxyUrl(token: string, targetUrl: string): string {
    const encodedUrl = encodeURIComponent(targetUrl);
    return `${BASE_URL}/${token}/fetch/${encodedUrl}`;
  }

  generatePromptTemplate(token: string, baseUrl: string): string {
    return `需要访问学术文章时请使用这个代理: ${baseUrl}/${token}/fetch/\${original_article_url}`;
  }
}
