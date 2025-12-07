import React, { useMemo } from 'react';
import { Card, Badge, OverlayTrigger, Tooltip } from 'react-bootstrap';
import { ShieldCheck, ExclamationTriangleFill } from 'react-bootstrap-icons';
import { getVendorInfo } from '../utils/securityVendors';

const verdictMeta = {
  malicious: { label: 'Malicious', variant: 'danger', icon: ExclamationTriangleFill },
  suspicious: { label: 'Suspicious', variant: 'warning', icon: ExclamationTriangleFill },
};

const SecurityVendorOverview = ({ results }) => {
  const vendors = useMemo(() => {
    if (!results) return [];
    return Object.entries(results)
      .filter(([, value]) => value && ['malicious', 'suspicious'].includes(value.category))
      .map(([engine, value]) => {
        const info = getVendorInfo(engine);
        return {
          engine,
          verdict: value.category,
          result: value.result || 'Detected threat',
          info,
        };
      });
  }, [results]);

  if (!vendors.length) {
    return (
      <Card className="glass-card mt-4 vendor-overview-card" text="light">
        <Card.Body className="d-flex flex-column flex-md-row justify-content-between align-items-start align-items-md-center gap-3">
          <div>
            <h5 className="mb-1">Security Vendor Overview</h5>
            <p className="mb-0" style={{ color: '#e2e8f0', fontWeight: 400 }}>
              No security vendors flagged this sample as dangerous.
            </p>
          </div>
          <Badge bg="success" pill>
            0 flagged
          </Badge>
        </Card.Body>
      </Card>
    );
  }

  const verdictCounts = vendors.reduce(
    (acc, vendor) => {
      acc[vendor.verdict] = (acc[vendor.verdict] || 0) + 1;
      return acc;
    },
    { malicious: 0, suspicious: 0 }
  );

  return (
    <Card className="glass-card mt-4 vendor-overview-card" text="light">
      <Card.Header className="d-flex flex-column flex-lg-row align-items-lg-center justify-content-between gap-3">
        <div>
          <h5 className="mb-1 d-flex align-items-center gap-2">
            <ShieldCheck size={18} />
            Security Vendor Overview
          </h5>
          <small style={{ color: '#e2e8f0', fontWeight: 400 }}>
            Summary of vendors that detected anomalies and their roles.
          </small>
        </div>
        <div className="d-flex gap-2 flex-wrap">
          {Object.entries(verdictCounts)
            .filter(([, count]) => count > 0)
            .map(([key, count]) => {
              const meta = verdictMeta[key];
              return (
                <Badge key={key} bg={meta?.variant || 'secondary'} pill>
                  {meta?.label || key}: {count}
                </Badge>
              );
            })}
        </div>
      </Card.Header>
      <Card.Body>
        <div className="vendor-overview-grid">
          {vendors.map((vendor) => {
            const meta = verdictMeta[vendor.verdict] || {};
            const Icon = meta.icon || ShieldCheck;
            return (
              <div key={vendor.engine} className="vendor-overview-item glass-card-subtle">
                <div className="d-flex justify-content-between align-items-start gap-2 mb-2">
                  <div>
                    <h6 className="mb-1">{vendor.info.displayName}</h6>
                    <small style={{ color: '#cbd5e1', fontWeight: 500 }}>{vendor.info.type}</small>
                  </div>
                  <OverlayTrigger
                    placement="top"
                    overlay={<Tooltip id={`vendor-${vendor.engine}`}>{vendor.result}</Tooltip>}
                  >
                    <Badge bg={meta.variant || 'secondary'}>
                      <Icon size={14} className="me-1" />
                      {meta.label || vendor.verdict}
                    </Badge>
                  </OverlayTrigger>
                </div>
                <p className="mb-0 vendor-overview-description">{vendor.info.description}</p>
              </div>
            );
          })}
        </div>
      </Card.Body>
    </Card>
  );
};

export default SecurityVendorOverview;
