import { useState } from 'react';
import { ApiClient } from '../api/client';
import { copyToClipboard } from '../utils/formatters';

interface TokenGeneratorProps {
  apiClient: ApiClient;
  baseUrl: string;
  onTokenGenerated: () => void;
}

export function TokenGenerator({ apiClient, baseUrl, onTokenGenerated }: TokenGeneratorProps) {
  const [expiryHours, setExpiryHours] = useState(2);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastToken, setLastToken] = useState<string | null>(null);

  const handleGenerate = async () => {
    setLoading(true);
    setError(null);

    try {
      const expiresAfter = expiryHours * 3600;
      const response = await apiClient.generateToken(expiresAfter);
      setLastToken(response.token);
      onTokenGenerated();
    } catch (err) {
      setError(err instanceof Error ? err.message : '生成令牌失败');
    } finally {
      setLoading(false);
    }
  };

  const handleCopyToken = () => {
    if (lastToken) {
      copyToClipboard(lastToken);
    }
  };

  const handleCopyPrompt = () => {
    if (lastToken) {
      const prompt = apiClient.generatePromptTemplate(lastToken, baseUrl);
      copyToClipboard(prompt);
    }
  };

  const handleCopyProxyUrl = () => {
    if (lastToken) {
      const url = apiClient.generateProxyUrl(lastToken, 'https://example.com');
      copyToClipboard(url);
    }
  };

  return (
    <div className="bg-white rounded-lg shadow-md p-6">
      <h2 className="text-xl font-semibold mb-4">生成访问令牌</h2>

      <div className="space-y-4">
        <div>
          <label htmlFor="expiry" className="block text-sm font-medium text-gray-700 mb-2">
            有效期（小时）
          </label>
          <div className="flex gap-2">
            <input
              id="expiry"
              type="number"
              min="0.5"
              step="0.5"
              value={expiryHours}
              onChange={(e) => setExpiryHours(Number(e.target.value))}
              className="flex-1 px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-primary-500"
              disabled={loading}
            />
            <button
              onClick={handleGenerate}
              disabled={loading}
              className="px-6 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700 disabled:opacity-50 disabled:cursor-not-allowed font-medium"
            >
              {loading ? '生成中...' : '生成令牌'}
            </button>
          </div>
        </div>

        {error && (
          <div className="p-3 bg-red-50 border border-red-200 rounded-md text-red-700 text-sm">
            {error}
          </div>
        )}

        {lastToken && (
          <div className="mt-6 space-y-4">
            <div className="p-4 bg-green-50 border border-green-200 rounded-md">
              <div className="flex justify-between items-center mb-2">
                <h3 className="font-medium text-green-900">令牌生成成功！</h3>
                <button
                  onClick={handleCopyToken}
                  className="text-sm text-green-700 hover:text-green-900 font-medium"
                >
                  复制令牌
                </button>
              </div>
              <code className="block text-xs bg-white p-2 rounded border text-gray-800 break-all">
                {lastToken}
              </code>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-4 bg-gray-50 border border-gray-200 rounded-md">
                <div className="flex justify-between items-center mb-2">
                  <h4 className="font-medium text-gray-900">提示词模板</h4>
                  <button
                    onClick={handleCopyPrompt}
                    className="text-sm text-primary-600 hover:text-primary-700 font-medium"
                  >
                    复制
                  </button>
                </div>
                <code className="block text-xs bg-white p-2 rounded border text-gray-800">
                  {apiClient.generatePromptTemplate(lastToken, baseUrl)}
                </code>
              </div>

              <div className="p-4 bg-gray-50 border border-gray-200 rounded-md">
                <div className="flex justify-between items-center mb-2">
                  <h4 className="font-medium text-gray-900">代理示例</h4>
                  <button
                    onClick={handleCopyProxyUrl}
                    className="text-sm text-primary-600 hover:text-primary-700 font-medium"
                  >
                    复制
                  </button>
                </div>
                <code className="block text-xs bg-white p-2 rounded border text-gray-800">
                  {apiClient.generateProxyUrl(lastToken, 'https://example.com/...')}
                </code>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
