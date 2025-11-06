import { useState, useEffect } from 'react';
import { Token } from '../types';
import { ApiClient } from '../api/client';
import { formatDateTime, formatTime, copyToClipboard } from '../utils/formatters';

interface TokenListProps {
  apiClient: ApiClient;
  refreshTrigger?: number;
}

export function TokenList({ apiClient, refreshTrigger }: TokenListProps) {
  const [tokens, setTokens] = useState<Token[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchTokens = async () => {
    setLoading(true);
    setError(null);

    try {
      const data = await apiClient.getTokens();
      // Ensure data is an array before sorting
      if (Array.isArray(data)) {
        setTokens(data.sort((a, b) => b.created_at - a.created_at));
      } else {
        setTokens([]);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : '获取令牌列表失败');
      setTokens([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTokens();
  }, [refreshTrigger]);

  const handleCopyToken = (token: string) => {
    copyToClipboard(token);
  };

  const isExpired = (expiresAt: number) => {
    return Date.now() / 1000 > expiresAt;
  };

  if (loading) {
    return (
      <div className="bg-white rounded-lg shadow-md p-6">
        <h2 className="text-xl font-semibold mb-4">活跃令牌</h2>
        <div className="flex items-center justify-center py-8 text-gray-500">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600"></div>
          <span className="ml-3">加载中...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-lg shadow-md p-6">
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-xl font-semibold">活跃令牌</h2>
        <button
          onClick={fetchTokens}
          className="text-sm text-primary-600 hover:text-primary-700 font-medium"
        >
          刷新
        </button>
      </div>

      {error && (
        <div className="p-3 bg-red-50 border border-red-200 rounded-md text-red-700 text-sm mb-4">
          {error}
        </div>
      )}

      {tokens.length === 0 ? (
        <div className="text-center py-8 text-gray-500">
          暂无活跃令牌
        </div>
      ) : (
        <div className="space-y-3">
          {tokens.map((token) => {
            const expired = isExpired(token.expires_at);
            return (
              <div
                key={token.token}
                className={`p-4 border rounded-md ${
                  expired ? 'bg-gray-50 border-gray-200' : 'bg-white border-gray-300'
                }`}
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-2">
                      <code className="text-sm font-mono break-all text-gray-800">
                        {token.token}
                      </code>
                      {!expired && (
                        <span className="px-2 py-1 text-xs bg-green-100 text-green-700 rounded-full whitespace-nowrap">
                          有效
                        </span>
                      )}
                      {expired && (
                        <span className="px-2 py-1 text-xs bg-gray-100 text-gray-500 rounded-full whitespace-nowrap">
                          已过期
                        </span>
                      )}
                    </div>
                    <div className="text-sm text-gray-600 space-y-1">
                      <div>创建时间: {formatDateTime(token.created_at)}</div>
                      <div>
                        过期时间: {formatDateTime(token.expires_at)}{' '}
                        <span className="text-gray-500">
                          ({formatTime(token.expires_at)})
                        </span>
                      </div>
                    </div>
                  </div>
                  <button
                    onClick={() => handleCopyToken(token.token)}
                    className="px-3 py-1 text-sm text-primary-600 hover:text-primary-700 border border-primary-200 rounded hover:bg-primary-50 whitespace-nowrap"
                  >
                    复制
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
