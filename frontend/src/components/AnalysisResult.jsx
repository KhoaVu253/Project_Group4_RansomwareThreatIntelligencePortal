import React from 'react';
import { Card, Tabs, Tab, Alert, ProgressBar, Table, Badge } from 'react-bootstrap';
import SecurityVendorOverview from './SecurityVendorOverview';
import FriendlyAnalysisSummary from './FriendlyAnalysisSummary';
import AIAnalysis from './AIAnalysis';

const renderThreatScore = (stats) => {
  if (!stats) return null;
  const total = stats.harmless + stats.malicious + stats.suspicious + stats.undetected;
  if (total === 0) return <p>No analysis statistics available from VirusTotal yet.</p>;

  const malicious = stats.malicious || 0;
  const suspicious = stats.suspicious || 0;
  const percent = total > 0 ? Math.round((malicious / total) * 100) : 0;

  let variant = 'success';
  if (percent > 50) {
    variant = 'danger';
  } else if (percent > 10) {
    variant = 'warning';
  }

  return (
    <div className="mt-3 threat-score-panel">
      <div className="d-flex justify-content-between align-items-end">
        <h5 className="mb-1">Threat Score</h5>
        <span className="threat-score-count">{malicious}/{total}</span>
      </div>
      <ProgressBar now={percent} variant={variant} label={`${percent}%`} animated className="threat-score-progress" />
      <div className="d-flex justify-content-between mt-2 text-muted threat-score-legend">
        <small>Malicious: {malicious}</small>
        <small>Suspicious: {suspicious}</small>
        <small>Safe: {stats.harmless || 0}</small>
      </div>
    </div>
  );
};

const DetectionsTable = ({ results }) => {
  if (!results) return null;
  return (
    <Table striped bordered hover variant="dark" responsive="sm" className="mt-3 detections-table">
      <thead>
        <tr>
          <th>Engine</th>
          <th>Category</th>
          <th>Result</th>
        </tr>
      </thead>
      <tbody>
        {Object.entries(results).map(([engine, result]) => (
          <tr key={engine}>
            <td style={{ color: '#e2e8f0', fontWeight: 400 }}>{engine}</td>
            <td>
              <Badge bg={result.category === 'malicious' ? 'danger' : 'secondary'}>
                {result.category}
              </Badge>
            </td>
            <td style={{ color: '#e2e8f0', fontWeight: 400 }}>{result.result || 'N/A'}</td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
};

const DetailsTab = ({ attributes }) => {
  return (
    <div className="mt-3">
      <p><strong>SHA-256:</strong> {attributes.sha256}</p>
      <p><strong>SHA-1:</strong> {attributes.sha1}</p>
      <p><strong>MD5:</strong> {attributes.md5}</p>
      <p><strong>File Size:</strong> {attributes.size} bytes</p>
      <p><strong>First Submission:</strong> {new Date(attributes.first_submission_date * 1000).toLocaleString()}</p>
      <p><strong>Last Analysis:</strong> {new Date(attributes.last_analysis_date * 1000).toLocaleString()}</p>
      <hr />
      <h5>Common Names:</h5>
      <ul>
        {attributes.names && attributes.names.map((name, index) => <li key={index}>{name}</li>)}
      </ul>
    </div>
  )
}

const AnalysisResult = ({ response, error, isLoading, activeQuery, backendBaseUrl }) => {
  if (isLoading) {
    return (
      <div className="d-flex justify-content-center my-4">
        <div className="spinner-border text-primary" style={{ width: '3rem', height: '3rem' }} role="status">
          <span className="visually-hidden">Loading...</span>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <Alert variant="danger" className="mt-4 shadow-lg">
        <Alert.Heading>Analysis Error</Alert.Heading>
        <p>{error.error?.message || 'An unknown error occurred.'}</p>
        <pre className="mb-0">Error Code: {error.error?.code || 'N/A'}</pre>
      </Alert>
    );
  }

  if (!response) {
    return <div className="text-center text-muted mt-4">Enter an indicator (IOC) to start analysis.</div>;
  }

  const attributes = response.data?.attributes;
  if (!attributes) {
    return <Alert variant="warning">Unable to read data returned from VirusTotal.</Alert>;
  }

  // Lấy indicator value từ activeQuery hoặc từ attributes
  const indicatorValue = activeQuery?.indicator || attributes.sha256 || attributes.url || attributes.domain || '';
  const indicatorType = activeQuery?.type || 'file';

  return (
    <Card text="light" className="analysis-card glass-card mt-4">
      <Card.Header>
        <h4 className="mb-0">Analysis Report</h4>
      </Card.Header>
      <Card.Body>
        <FriendlyAnalysisSummary
          stats={attributes.last_analysis_stats}
          results={attributes.last_analysis_results}
        />
        
        {/* AI Analysis Component - Right below the Overview section */}
        {response && attributes && indicatorValue && backendBaseUrl && (
          <AIAnalysis
            vtData={response}
            indicatorType={indicatorType}
            indicatorValue={indicatorValue}
            backendBaseUrl={backendBaseUrl}
          />
        )}
        
        {renderThreatScore(attributes.last_analysis_stats)}
        <SecurityVendorOverview results={attributes.last_analysis_results} />
      </Card.Body>
      <Card.Body>
        <Tabs defaultActiveKey="detections" id="result-tabs" className="mb-3" fill>
          <Tab eventKey="detections" title="Detections">
            <DetectionsTable results={attributes.last_analysis_results} />
          </Tab>
          <Tab eventKey="details" title="Details">
            <DetailsTab attributes={attributes} />
          </Tab>
          <Tab eventKey="raw" title="Raw JSON">
            <pre className="p-3 bg-dark rounded" style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
              {JSON.stringify(response, null, 2)}
            </pre>
          </Tab>
        </Tabs>
      </Card.Body>
    </Card>
  );
};

export default AnalysisResult;
