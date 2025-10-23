import React from 'react';
import { Container, Row, Col, Tabs, Tab, Card, Badge, Button } from 'react-bootstrap';
import { ShieldCheck, LightningChargeFill, Globe2, BarChartFill, ArrowRightCircle } from 'react-bootstrap-icons';

import FileUpload from '../components/FileUpload';
import IndicatorForm from '../components/IndicatorForm';

const iconDictionary = {
  ShieldCheck,
  LightningChargeFill,
  Globe2,
  BarChartFill,
};

const Dashboard = ({
  metrics,
  highlightCards,
  onAnalyze,
  onFileUpload,
  onClear,
  isLoading,
  onScrollToConsole,
  consoleRef,
}) => {
  return (
    <Container className="py-5 position-relative">
      <section className="hero-section text-center mb-5">
        <Badge bg="primary" pill className="hero-eyebrow">
          Ransomware Threat Analysis
        </Badge>
        <h1 className="hero-title mt-3">Proactive Threat Detection & Analysis</h1>
        <p className="hero-subtitle">
          Leverage VirusTotal technology to scan files, URLs, domains, and IP addresses, detecting ransomware threats quickly and accurately
        </p>

        <div className="hero-actions d-flex justify-content-center gap-3 mt-4">
          <Button size="lg" variant="primary" className="hero-cta-main" onClick={onScrollToConsole}>
            Start Scanning Now
          </Button>
        </div>

        <Row className="hero-metrics g-3 justify-content-center mt-4">
          {metrics.map(({ label, value, caption }) => (
            <Col xs={10} sm={6} md={4} key={label}>
              <div className="metric-card glass-card">
                <span className="metric-value">{value}</span>
                <span className="metric-label">{label}</span>
                <small className="metric-caption">{caption}</small>
              </div>
            </Col>
          ))}
        </Row>
      </section>

      <Row className="justify-content-center" ref={consoleRef}>
        <Col lg={10} xl={9}>
          <Card className="vt-tabs-card glass-card shadow-none border-0">
            <Card.Header className="vt-tabs-card__header px-4 py-3">
              <div>
                <h4 className="card-title mb-1">Analysis Console</h4>
                <span className="card-subtitle text-muted">
                  Scan files, URLs, domains, or IPs to identify threats
                </span>
              </div>
            </Card.Header>
            <Card.Body className="px-4 pb-4">
              <Tabs defaultActiveKey="file" id="main-tabs" className="mb-3 vt-tabs" fill>
                <Tab eventKey="file" title="File / Hash">
                  <FileUpload onFileUpload={onFileUpload} isLoading={isLoading} />
                </Tab>
                <Tab eventKey="url" title="URL">
                  <IndicatorForm
                    onSubmit={onAnalyze}
                    onClear={onClear}
                    isLoading={isLoading}
                    type="url"
                    placeholder="Enter suspicious URL"
                  />
                </Tab>
                <Tab eventKey="search" title="Hash / Domain / IP">
                  <IndicatorForm
                    onSubmit={onAnalyze}
                    onClear={onClear}
                    isLoading={isLoading}
                    type="search"
                    placeholder="Enter hash, domain, or IP"
                  />
                </Tab>
              </Tabs>

              <div className="console-note glass-card mt-3 d-flex align-items-center justify-content-between gap-3">
                <div>
                  <h6 className="mb-1">Support for Multiple Data Types</h6>
                  <p className="mb-0 text-muted">
                    Upload files, check URLs, lookup domains, or scan IP addresses with VirusTotal API
                  </p>
                </div>
                <ArrowRightCircle size={28} className="text-primary" />
              </div>
            </Card.Body>
          </Card>
        </Col>
      </Row>

      <Row className="threat-highlights g-4 mt-4">
        {highlightCards.map(({ icon, title, description }) => {
          const IconComponent = iconDictionary[icon] ?? ShieldCheck;
          return (
            <Col md={6} lg={3} key={title}>
              <div className="highlight-card glass-card h-100">
                <div className="highlight-icon">
                  <IconComponent size={26} />
                </div>
                <h5 className="highlight-title">{title}</h5>
                <p className="highlight-description">{description}</p>
              </div>
            </Col>
          );
        })}
      </Row>
    </Container>
  );
};

export default Dashboard;
