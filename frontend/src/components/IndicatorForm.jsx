
import React, { useState, useEffect } from 'react';
import { Form, Row, Col, Button, InputGroup } from 'react-bootstrap';
import { Search } from 'react-bootstrap-icons';

// A more generic form for submitting URL or other indicators (hash, domain, ip)
const IndicatorForm = ({ onSubmit, onClear, isLoading, type, placeholder }) => {
  const [indicator, setIndicator] = useState('');
  // The type of indicator being submitted (e.g., 'url', 'file', 'domain')
  const [submissionType, setSubmissionType] = useState('file');

  useEffect(() => {
    // If the form type is fixed (like for the URL tab), set it once.
    if (type === 'url') {
      setSubmissionType('url');
    } else {
      // Default for search tab
      setSubmissionType('file');
    }
  }, [type]);

  const handleSubmit = (e) => {
    e.preventDefault();
    if (indicator) {
      onSubmit({ indicator, type: submissionType });
    }
  };

  const handleClearClick = () => {
    setIndicator('');
    onClear();
  }

  return (
    <Form onSubmit={handleSubmit} className="indicator-form">
      <Row className="g-2 align-items-end">
        <Col md>
          <InputGroup className="indicator-input-group">
            <InputGroup.Text className="indicator-input-prefix">
              {type === 'url' ? 'URL' : 'IOC'}
            </InputGroup.Text>
            <Form.Control
              type="text"
              id={`indicatorInput-${type}`}
              placeholder={placeholder}
              value={indicator}
              onChange={(e) => setIndicator(e.target.value)}
              required
              className="vt-input"
            />
          </InputGroup>
        </Col>
        
        {type === 'search' && (
            <Col md={4}>
                <Form.Select 
                    id="typeSelect-search"
                    value={submissionType}
                    onChange={(e) => setSubmissionType(e.target.value)}
                    className="vt-input"
                >
                    <option value="file">File Hash</option>
                    <option value="domain">Domain</option>
                    <option value="ip_address">IP Address</option>
                </Form.Select>
            </Col>
        )}

        <Col md="auto">
          <Button type="submit" variant="primary" disabled={isLoading || !indicator} className="w-100 vt-submit-btn">
            {isLoading ? (
              <span className="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>
            ) : (
              <Search />
            )}
          </Button>
        </Col>
        {indicator && (
          <Col md="auto">
            <Button
              type="button"
              variant="outline-light"
              disabled={isLoading}
              className="indicator-clear-btn w-100"
              onClick={handleClearClick}
            >
              Clear
            </Button>
          </Col>
        )}
      </Row>
    </Form>
  );
};

export default IndicatorForm;
