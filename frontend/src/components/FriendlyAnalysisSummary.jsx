import React, { useMemo } from 'react';
import { Badge } from 'react-bootstrap';
import {
  determineRiskLevel,
  buildHumanReadableReasons,
  getRecommendedActions,
  summarizeStats,
} from '../utils/analysisSummary';

const FriendlyAnalysisSummary = ({ stats, results }) => {
  const normalizedStats = useMemo(() => summarizeStats(stats), [stats]);
  const risk = useMemo(() => determineRiskLevel(stats), [stats]);
  const reasons = useMemo(() => buildHumanReadableReasons(results), [results]);
  const actions = useMemo(() => getRecommendedActions(risk.level), [risk.level]);

  const badgeText =
    normalizedStats.total > 0
      ? `${normalizedStats.malicious}/${normalizedStats.total} nhà cung cấp cảnh báo`
      : '0 nhà cung cấp cảnh báo';

  return (
    <div className="friendly-summary glass-card-subtle mb-4">
      <div className="d-flex flex-column flex-lg-row justify-content-between align-items-start align-items-lg-center gap-3">
        <div>
          <p className="friendly-summary__eyebrow text-uppercase mb-1">Tổng quan</p>
          <h4 className="mb-1">{risk.label}</h4>
          <p className="mb-0" style={{ color: '#f4f6fb' }}>
            {risk.description}
          </p>
          <small className="d-block mt-2" style={{ color: '#e0e6f6' }}>
            Nguy hiểm: {normalizedStats.malicious} · Đáng ngờ: {normalizedStats.suspicious} · An toàn:{' '}
            {normalizedStats.harmless}
          </small>
        </div>
        <Badge bg={risk.variant} pill className="friendly-summary__badge">
          {badgeText}
        </Badge>
      </div>

      {reasons.length > 0 && (
        <div className="friendly-summary__section mt-3">
          <p className="fw-semibold mb-2">Lý do chính</p>
          <ul className="friendly-summary__list">
            {reasons.map((reason, index) => (
              <li key={index}>{reason}</li>
            ))}
          </ul>
        </div>
      )}

      {actions.length > 0 && (
        <div className="friendly-summary__section mt-3">
          <p className="fw-semibold mb-2">Khuyến nghị</p>
          <ul className="friendly-summary__list">
            {actions.map((action, index) => (
              <li key={index}>{action}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};

export default FriendlyAnalysisSummary;
