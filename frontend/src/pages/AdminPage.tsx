import { useEffect, useState } from 'react';
import { ApiClient } from '../api/client';
import { TokenGenerator } from '../components/TokenGenerator';
import { TokenList } from '../components/TokenList';
import { HealthResponse } from '../types';

export function AdminPage() {
  const adminToken = new URLSearchParams(window.location.search).get('admin_token');

  const [apiClient, setApiClient] = useState<ApiClient | null>(null);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [refreshTrigger, setRefreshTrigger] = useState(0);
  const [error, setError] = useState<string | null>(null);

  const baseUrl = window.location.origin;

  useEffect(() => {
    if (adminToken) {
      setApiClient(new ApiClient(adminToken));
    }
  }, [adminToken]);

  useEffect(() => {
    if (apiClient) {
      apiClient.getHealth()
        .then(setHealth)
        .catch((err) => setError(err.message));
    }
  }, [apiClient]);

  if (!adminToken) {
    return (
      <div className="min-h-screen bg-gray-100 flex items-center justify-center p-4">
        <div className="bg-white rounded-lg shadow-md p-8 max-w-md w-full">
          <h1 className="text-2xl font-bold text-red-600 mb-4">访问被拒绝</h1>
          <p className="text-gray-700 mb-4">
            缺少管理员令牌。请确保在 URL 中包含正确的 admin_token 参数。
          </p>
          <p className="text-sm text-gray-500 font-mono">
            示例: {window.location.origin}/admin?admin_token=your-token
          </p>
        </div>
      </div>
    );
  }

  if (!apiClient) {
    return (
      <div className="min-h-screen bg-gray-100 flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600"></div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-100">
      <header className="bg-white shadow-sm">
        <div className="max-w-7xl mx-auto px-4 py-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center">
            <div>
              <h1 className="text-2xl font-bold text-gray-900">
                Webpage Reverse Proxy
              </h1>
              <p className="text-sm text-gray-500 mt-1">
                学术资源代理管理界面
              </p>
            </div>
            {health && (
              <div className="text-right">
                <div className="text-sm text-gray-600">
                  服务状态: <span className="text-green-600 font-medium">正常</span>
                </div>
                <div className="text-xs text-gray-500">
                  运行时间: {Math.floor(health.uptime / 3600)}小时
                </div>
              </div>
            )}
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 py-6 sm:px-6 lg:px-8">
        {error && (
          <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-md text-red-700">
            {error}
          </div>
        )}

        <div className="space-y-6">
          <TokenGenerator
            apiClient={apiClient}
            baseUrl={baseUrl}
            onTokenGenerated={() => setRefreshTrigger(prev => prev + 1)}
          />

          <TokenList
            apiClient={apiClient}
            refreshTrigger={refreshTrigger}
          />
        </div>
      </main>

      <footer className="bg-white border-t border-gray-200 mt-12">
        <div className="max-w-7xl mx-auto px-4 py-4 sm:px-6 lg:px-8">
          <p className="text-center text-sm text-gray-500">
            Webpage Reverse Proxy - 基于 Node.js 的学术资源代理服务器
          </p>
        </div>
      </footer>
    </div>
  );
}
