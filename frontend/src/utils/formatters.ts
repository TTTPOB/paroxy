export function formatTime(timestamp: number): string {
  const now = new Date();
  const diff = timestamp * 1000 - now.getTime();
  const absDiff = Math.abs(diff);

  if (absDiff < 60000) {
    return '刚刚';
  } else if (absDiff < 3600000) {
    const minutes = Math.floor(absDiff / 60000);
    return diff > 0 ? `${minutes}分钟后` : `${minutes}分钟前`;
  } else if (absDiff < 86400000) {
    const hours = Math.floor(absDiff / 3600000);
    return diff > 0 ? `${hours}小时后` : `${hours}小时前`;
  } else {
    const days = Math.floor(absDiff / 86400000);
    return diff > 0 ? `${days}天后` : `${days}天前`;
  }
}

export function formatDateTime(timestamp: number): string {
  return new Date(timestamp * 1000).toLocaleString('zh-CN');
}

export function copyToClipboard(text: string): Promise<void> {
  return navigator.clipboard.writeText(text);
}
