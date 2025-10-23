import React, { useMemo, useState } from 'react';
import {
  Container,
  Row,
  Col,
  Card,
  Table,
  Form,
  Button,
  Badge,
  Modal,
} from 'react-bootstrap';
import AnalysisResult from '../components/AnalysisResult';

const severityStatus = (entry) => {
  if ((entry?.malicious || 0) > 0) return 'malicious';
  if ((entry?.suspicious || 0) > 0) return 'suspicious';
  return 'clean';
};

const severityMeta = {
  malicious: { label: 'Malicious', variant: 'danger' },
  suspicious: { label: 'Suspicious', variant: 'warning' },
  clean: { label: 'Safe', variant: 'success' },
};

const typeLabels = {
  file: 'File hash',
  url: 'URL',
  domain: 'Domain',
  ip_address: 'IP Address',
};

const downloadCsv = (entries) => {
  const header = [
    'Time',
    'Type',
    'Value',
    'Summary',
    'Malicious',
    'Suspicious',
    'Safe',
    'Undetected',
    'Total Engines',
  ];
  const rows = entries.map((entry) => [
    new Date(entry.savedAt).toLocaleString(),
    typeLabels[entry.type] || entry.type,
    entry.display || entry.indicator || '',
    entry.summary || '',
    entry.malicious ?? 0,
    entry.suspicious ?? 0,
    entry.harmless ?? 0,
    entry.undetected ?? 0,
    entry.total ?? '',
  ]);

  const csvContent = [header, ...rows]
    .map((row) =>
      row
        .map((value) => {
          const stringValue = String(value ?? '');
          if (stringValue.includes('"') || stringValue.includes(',') || stringValue.includes('\n')) {
            return `"${stringValue.replace(/"/g, '""')}"`;
          }
          return stringValue;
        })
        .join(',')
    )
    .join('\n');

  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `scan_history_${Date.now()}.csv`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
};

const HistoryPage = ({ entries, onReanalyze, onClear }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [selectedEntry, setSelectedEntry] = useState(null);

  const filteredEntries = useMemo(() => {
    return (entries || [])
      .filter((entry) => {
        if (!entry) return false;

        const severity = severityStatus(entry);
        const matchesSeverity =
          severityFilter === 'all' || (severityFilter === severity && severity !== undefined);
        const matchesType = typeFilter === 'all' || entry.type === typeFilter;
        const normalizedSearch = searchTerm.trim().toLowerCase();
        const matchesSearch =
          !normalizedSearch ||
          (entry.display || '').toLowerCase().includes(normalizedSearch) ||
          (entry.indicator || '').toLowerCase().includes(normalizedSearch) ||
          (entry.summary || '').toLowerCase().includes(normalizedSearch);

        return matchesSeverity && matchesType && matchesSearch;
      })
      .sort((a, b) => new Date(b.savedAt) - new Date(a.savedAt));
  }, [entries, severityFilter, typeFilter, searchTerm]);

  return (
    <Container className="history-page py-5">
      <Row className="mb-4">
        <Col>
          <div className="d-flex flex-column flex-lg-row justify-content-between gap-3 align-items-lg-center">
            <div>
              <h2 className="mb-1">Your Scan History</h2>
              <p className="text-muted mb-0">
                Summary of recently analyzed IOCs. You can review reports, filter by severity, or download.
              </p>
            </div>
            <div className="d-flex gap-2">
              <Button
                variant="outline-light"
                onClick={() => downloadCsv(filteredEntries)}
                disabled={!filteredEntries.length}
              >
                Export CSV
              </Button>
              <Button
                variant="outline-danger"
                onClick={() => onClear?.()}
                disabled={!entries?.length}
              >
                Clear History
              </Button>
            </div>
          </div>
        </Col>
      </Row>

      <Row className="mb-3 g-3">
        <Col lg={4} md={6}>
          <Form.Control
            type="text"
            placeholder="Search by value or summary"
            value={searchTerm}
            onChange={(event) => setSearchTerm(event.target.value)}
            className="vt-input"
          />
        </Col>
        <Col lg={4} md={3} sm={6}>
          <Form.Select
            className="vt-input"
            value={typeFilter}
            onChange={(event) => setTypeFilter(event.target.value)}
          >
            <option value="all">All Types</option>
            <option value="file">File hash</option>
            <option value="url">URL</option>
            <option value="domain">Domain</option>
            <option value="ip_address">IP Address</option>
          </Form.Select>
        </Col>
        <Col lg={4} md={3} sm={6}>
          <Form.Select
            className="vt-input"
            value={severityFilter}
            onChange={(event) => setSeverityFilter(event.target.value)}
          >
            <option value="all">All Severity Levels</option>
            <option value="malicious">Malicious</option>
            <option value="suspicious">Suspicious</option>
            <option value="clean">Safe</option>
          </Form.Select>
        </Col>
      </Row>

      <Row>
        <Col>
          <Card className="glass-card history-table-card">
            <Card.Body className="p-0">
              <Table responsive hover variant="dark" className="mb-0 history-table">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Type</th>
                    <th>Value</th>
                    <th>Result</th>
                    <th>Severity</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredEntries.length === 0 && (
                    <tr>
                      <td colSpan={6} className="text-center text-muted py-4">
                        No matching records found.
                      </td>
                    </tr>
                  )}
                  {filteredEntries.map((entry) => {
                    const severity = severityStatus(entry);
                    const severityInfo = severityMeta[severity] || severityMeta.clean;
                    return (
                      <tr key={entry.id}>
                        <td>{new Date(entry.savedAt).toLocaleString()}</td>
                        <td>
                          <Badge bg="secondary">
                            {typeLabels[entry.type] || entry.type || 'Unknown'}
                          </Badge>
                        </td>
                        <td className="history-indicator-cell">
                          <span title={entry.display || entry.indicator}>
                            {entry.display || entry.indicator}
                          </span>
                        </td>
                        <td>{entry.summary || 'No summary data'}</td>
                        <td>
                          <Badge bg={severityInfo.variant}>
                            {severityInfo.label} {entry.malicious}/{entry.total || '—'}
                          </Badge>
                        </td>
                        <td className="history-actions">
                          <Button
                            size="sm"
                            variant="outline-light"
                            onClick={() => setSelectedEntry(entry)}
                          >
                            View Report
                          </Button>
                          <Button
                            size="sm"
                            variant="primary"
                            onClick={() => onReanalyze?.(entry)}
                          >
                            Re-analyze
                          </Button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </Table>
            </Card.Body>
          </Card>
        </Col>
      </Row>

      <Modal
        show={Boolean(selectedEntry)}
        onHide={() => setSelectedEntry(null)}
        size="xl"
        centered
        dialogClassName="history-modal"
      >
        <Modal.Header closeButton>
          <Modal.Title>Detailed Report</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          {selectedEntry && (
            <AnalysisResult response={selectedEntry.response} error={null} isLoading={false} />
          )}
        </Modal.Body>
      </Modal>
    </Container>
  );
};

export default HistoryPage;
