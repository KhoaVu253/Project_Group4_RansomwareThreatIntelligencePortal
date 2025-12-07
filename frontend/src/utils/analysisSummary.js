import { getVendorInfo } from './securityVendors';

const RISK_LEVELS = {
  safe: {
    label: 'An toàn',
    variant: 'success',
    description: 'Không có nhà cung cấp nào ghi nhận dấu hiệu nguy hiểm.',
  },
  caution: {
    label: 'Cần lưu ý',
    variant: 'warning',
    description: 'Một số nhà cung cấp nghi ngờ có hành vi bất thường, nên tiếp tục theo dõi.',
  },
  danger: {
    label: 'Nguy hiểm',
    variant: 'danger',
    description: 'Nhiều nhà cung cấp cảnh báo mã độc. Khuyến nghị cách ly ngay.',
  },
};

const normalizeStats = (stats = {}) => {
  const malicious = Number(stats.malicious) || 0;
  const suspicious = Number(stats.suspicious) || 0;
  const harmless = Number(stats.harmless) || 0;
  const undetected = Number(stats.undetected) || 0;
  const total = malicious + suspicious + harmless + undetected;
  return { malicious, suspicious, harmless, undetected, total };
};

export const determineRiskLevel = (stats = {}) => {
  const { malicious, suspicious, total } = normalizeStats(stats);
  const maliciousRatio = total > 0 ? malicious / total : 0;

  if (malicious >= 3 || maliciousRatio >= 0.05) {
    return { level: 'danger', ...RISK_LEVELS.danger };
  }
  if (malicious > 0 || suspicious >= 2) {
    return { level: 'caution', ...RISK_LEVELS.caution };
  }
  if (suspicious === 1) {
    return {
      level: 'caution',
      ...RISK_LEVELS.caution,
      description: 'Có một nhà cung cấp nghi ngờ. Hãy xác minh trước khi sử dụng.',
    };
  }
  return { level: 'safe', ...RISK_LEVELS.safe };
};

export const buildHumanReadableReasons = (results = {}, limit = 3) => {
  const flagged = Object.entries(results)
    .filter(
      ([, data]) =>
        data &&
        typeof data === 'object' &&
        ['malicious', 'suspicious'].includes(data.category)
    )
    .slice(0, limit)
    .map(([engine, data]) => {
      const info = getVendorInfo(engine);
      const verdict =
        data.category === 'malicious' ? 'phát hiện mã độc' : 'cảnh báo hành vi bất thường';
      const detail = data.result ? `(${data.result})` : '';
      return `${info.displayName} ${verdict} ${detail}`.trim();
    });
  return flagged;
};

export const getRecommendedActions = (level) => {
  switch (level) {
    case 'danger':
      return [
        'Không mở hoặc chia sẻ file/URL này.',
        'Cách ly hoặc xóa khỏi hệ thống an toàn.',
        'Thông báo cho đội IT/SOC để điều tra thêm.',
      ];
    case 'caution':
      return [
        'Không thực thi file cho đến khi được xác minh.',
        'Quét lại bằng giải pháp bảo mật nội bộ.',
        'Kiểm tra nguồn gốc file/URL trước khi sử dụng.',
      ];
    default:
      return [
        'Không có cảnh báo nào, nhưng vẫn nên cẩn trọng nếu nguồn không đáng tin.',
        'Giữ phần mềm bảo mật cập nhật và theo dõi nếu có dấu hiệu bất thường.',
      ];
  }
};

export const summarizeStats = (stats = {}) => normalizeStats(stats);
