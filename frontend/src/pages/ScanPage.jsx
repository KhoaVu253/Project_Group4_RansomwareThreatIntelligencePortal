import React, { useMemo } from 'react';
import { Container, Row, Col, Button, Badge, Alert, ProgressBar } from 'react-bootstrap';
import { ArrowLeft, ArrowRepeat } from 'react-bootstrap-icons';

import AnalysisResult from '../components/AnalysisResult';

const typeLabels = {
  file: 'File hash',
  url: 'URL',
  domain: 'Domain',
  ip_address: 'IP Address',
};

const truncateIndicator = (value) => {
  if (!value) return '';
  if (value.length <= 48) return value;
  return `${value.slice(0, 24)}…${value.slice(-16)}`;
};

const statusMappings = {
  idle: { variant: 'secondary', text: 'Ready' },
  lookup: { variant: 'info', text: 'Looking up' },
  completed: { variant: 'success', text: 'Completed' },
  uploading: { variant: 'warning', text: 'Uploading' },
  polling: { variant: 'info', text: 'Waiting for results' },
  queued: { variant: 'info', text: 'Queued' },
  running: { variant: 'info', text: 'Analyzing' },
  'in-progress': { variant: 'info', text: 'Analyzing' },
  timeout: { variant: 'warning', text: 'Timeout' },
  error: { variant: 'danger', text: 'Scan failed' },
};

const ScanPage = ({ response, error, isLoading, activeQuery, analysisStatus, progressPercent, onBack, onRetry, backendBaseUrl }) => {
  const hasQuery = Boolean(activeQuery?.indicator || activeQuery?.display);
  const primaryLabel = activeQuery?.display || activeQuery?.indicator;
  const secondaryLabel =
    activeQuery?.indicator && activeQuery?.display && activeQuery.display !== activeQuery.indicator
      ? activeQuery.indicator
      : null;
  const shouldShowProgress =
    hasQuery &&
    progressPercent > 0 &&
    (progressPercent < 100 || ['uploading', 'polling', 'queued', 'running', 'in-progress'].includes(analysisStatus));

  const statusBadge = useMemo(() => {
    if (!hasQuery) {
      return { variant: 'secondary', text: 'No task' };
    }
    if (analysisStatus && statusMappings[analysisStatus]) {
      return statusMappings[analysisStatus];
    }
    if (isLoading) {
      return { variant: 'info', text: 'Scanning...' };
    }
    if (error) {
      return { variant: 'danger', text: 'Scan failed' };
    }
    if (response) {
      return { variant: 'success', text: 'Completed' };
    }
    return { variant: 'secondary', text: 'Ready' };
  }, [hasQuery, isLoading, error, response]);

  const titleText = (() => {
    if (!hasQuery) return 'No analysis yet';
    if (statusBadge.text === 'Completed' || analysisStatus === 'completed') {
      if (activeQuery?.summary) return activeQuery.summary;
      if (response?.data?.attributes?.last_analysis_stats) {
        const stats = response.data.attributes.last_analysis_stats;
        const malicious = stats.malicious || 0;
        const suspicious = stats.suspicious || 0;
        if (malicious > 0) return `${malicious} vendors flagged this object as malicious.`;
        if (suspicious > 0) return `${suspicious} vendors flagged this object as suspicious.`;
        return 'No vendors flagged this object as malicious.';
      }
    }
    if (analysisStatus === 'uploading') return 'Processing data...';
    if (['polling', 'queued', 'running', 'in-progress'].includes(analysisStatus)) return 'Processing data...';
    if (analysisStatus === 'timeout') return 'Analysis did not complete within the default timeout. You can try scanning again to continue monitoring.';
    if (analysisStatus === 'error') return 'An error occurred during analysis.';
    return 'Processing indicator';
  })();

  return (
    <Container className="scan-page py-5">
      <Row className="align-items-center justify-content-between g-3 mb-4">
        <Col lg={7}>
          <div className="scan-summary glass-card">
            <div className="d-flex align-items-center gap-2 mb-3">
              <Badge bg="primary">{typeLabels[activeQuery?.type] || 'Analysis'}</Badge>
              <Badge bg={statusBadge.variant}>{statusBadge.text}</Badge>
            </div>
            {hasQuery ? (
              <>
                <h2 className="scan-summary__title mb-2">{titleText}</h2>
                <p className="scan-summary__indicator mb-0">{truncateIndicator(primaryLabel)}</p>
                {secondaryLabel && (
                  <p className="scan-summary__indicator mt-2 mb-0 text-muted">
                    Hash: {truncateIndicator(secondaryLabel)}
                  </p>
                )}
              </>
            ) : (
              <>
                <h2 className="scan-summary__title mb-2">No analysis yet</h2>
                <p className="scan-summary__indicator mb-0">
                  Return to the console to drag & drop a file or enter an indicator to check.
                </p>
              </>
            )}

            {shouldShowProgress && (
              <div className="scan-progress mt-4">
                <div className="d-flex justify-content-between align-items-center mb-2">
                  <span className="scan-progress__label">Progress</span>
                  <span className="scan-progress__value">{Math.min(100, Math.round(progressPercent))}%</span>
                </div>
                <ProgressBar
                  now={Math.min(100, progressPercent)}
                  animated={!['completed', 'error', 'timeout'].includes(analysisStatus)}
                  variant={
                    analysisStatus === 'error'
                      ? 'danger'
                      : analysisStatus === 'timeout'
                        ? 'warning'
                        : 'info'
                  }
                  className="scan-progress-bar"
                />
              </div>
            )}
          </div>
        </Col>
        <Col lg="auto" className="scan-actions d-flex gap-2">
          <Button variant="outline-light" className="scan-action-btn" onClick={onBack}>
            <ArrowLeft size={18} className="me-2" />
            Back to Console
          </Button>
          <Button
            variant="primary"
            className="scan-action-btn"
            onClick={onRetry}
            disabled={
              !hasQuery || isLoading || ['uploading', 'polling', 'queued', 'running', 'in-progress'].includes(analysisStatus)
            }
          >
            <ArrowRepeat size={18} className="me-2" />
            Rescan
          </Button>
        </Col>
      </Row>

      {!hasQuery && (
        <Alert variant="secondary" className="glass-card scan-empty-alert">
          <Alert.Heading>No Data</Alert.Heading>
          <p className="mb-0">
            Return to the main page and drop a file, URL, or other indicator to start a scan session.
          </p>
        </Alert>
      )}

      {hasQuery && (
        <AnalysisResult 
          response={response} 
          error={error} 
          isLoading={isLoading}
          activeQuery={activeQuery}
          backendBaseUrl={backendBaseUrl}
        />
      )}
    </Container>
  );
};

export default ScanPage;
