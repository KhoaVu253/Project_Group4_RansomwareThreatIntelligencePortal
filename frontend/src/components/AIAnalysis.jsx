import React, { useState } from 'react';
import { Card, Button, Spinner, Alert } from 'react-bootstrap';
import { Lightning, LightningFill } from 'react-bootstrap-icons';
import axios from 'axios';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

const AIAnalysis = ({ vtData, indicatorType, indicatorValue, backendBaseUrl }) => {
  const [analysis, setAnalysis] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);

  // Lấy token từ localStorage
  const getToken = () => {
    try {
      return localStorage.getItem('vt-auth-token') || null;
    } catch (err) {
      console.error('Failed to get token:', err);
      return null;
    }
  };

  const handleAnalyze = async () => {
    if (!vtData || !indicatorValue) {
      setError({
        message: 'No data available for AI analysis.',
        code: null,
      });
      return;
    }

    const token = getToken();
    if (!token) {
      setError({
        message: 'Please sign in to run AI analysis.',
        code: null,
      });
      return;
    }

    setIsLoading(true);
    setError(null);
    setAnalysis(null);

    try {
      const response = await axios.post(
        `${backendBaseUrl}/api/ai/analyze`,
        {
          vt_data: vtData,
          indicator_type: indicatorType,
          indicator_value: indicatorValue,
        },
        {
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        }
      );

      setAnalysis(response.data.analysis);
    } catch (err) {
      const errorData = err.response?.data || {};
      const errorMsg = errorData.error || 'Unexpected error during AI analysis.';
      const errorCode = errorData.error_code;
      const retryAfter = errorData.retry_after;
      
      // Handle specific error codes
      let displayError = errorMsg;
      if (errorCode === 'RATE_LIMIT_EXCEEDED') {
        displayError = `⚠️ Gemini rate limit reached${retryAfter ? ` — retry in ${retryAfter}s` : ''}.`;
      } else if (errorCode === 'TIMEOUT') {
        displayError = '⏱️ Gemini did not respond in time. Please try again.';
      } else if (errorCode === 'AUTHENTICATION_FAILED' || errorCode === 'ACCESS_FORBIDDEN') {
        displayError = '🔐 Gemini credentials are invalid or lack permission.';
      } else if (errorCode === 'SAFETY_BLOCKED') {
        displayError = '🛡️ Gemini blocked this content for safety reasons.';
      }
      
      setError({
        message: displayError,
        code: errorCode || null,
      });
      console.error('AI Analysis Error:', err);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Card 
      className="mt-4 glass-card" 
      style={{ 
        background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
        border: 'none',
        borderRadius: '12px',
        boxShadow: '0 8px 32px rgba(102, 126, 234, 0.3)'
      }}
    >
      <Card.Body className="p-4">
        {!analysis && !isLoading && (
          <div className="d-flex align-items-center justify-content-between flex-wrap gap-3">
            <div className="d-flex align-items-center gap-3">
              <LightningFill size={32} className="text-white" style={{ filter: 'drop-shadow(0 2px 4px rgba(0,0,0,0.2))' }} />
              <div>
                <h5 className="mb-0 text-white fw-bold">AI Security Analyst</h5>
                <small className="text-white-50 d-block">Powered by Gemini AI</small>
              </div>
            </div>
            <Button
              variant="primary"
              onClick={handleAnalyze}
              disabled={!vtData || !indicatorValue}
              className="d-flex align-items-center gap-2"
              style={{
                background: 'linear-gradient(135deg, #4facfe 0%, #00f2fe 100%)',
                border: 'none',
                fontWeight: '600',
                padding: '10px 20px',
                borderRadius: '8px',
                boxShadow: '0 4px 15px rgba(79, 172, 254, 0.4)'
              }}
            >
              <Lightning size={18} />
              Run analysis
            </Button>
          </div>
        )}

        {isLoading && (
          <div className="text-center py-4">
            <Spinner animation="border" variant="light" className="mb-3" style={{ width: '3rem', height: '3rem' }} />
            <p className="text-white mb-0 fw-semibold">Analyzing with Gemini...</p>
            <small className="text-white-50 d-block mt-2">Please wait a moment.</small>
          </div>
        )}

        {error && (
          <Alert variant="danger" className="mt-3" style={{ borderRadius: '8px' }}>
            <Alert.Heading className="h6 d-flex align-items-center gap-2">
              <LightningFill size={16} />
              Analysis error
            </Alert.Heading>
            <p className="mb-0">{error.message}</p>
            {error.code === 'RATE_LIMIT_EXCEEDED' && (
              <small className="text-muted d-block mt-2">
                💡 Tip: Gemini API enforces per-minute limits. Please wait 1–2 minutes before retrying.
              </small>
            )}
          </Alert>
        )}

        {analysis && (
          <div className="mt-3">
            <div className="d-flex align-items-center justify-content-between mb-3 flex-wrap gap-2">
              <div className="d-flex align-items-center gap-2">
                <LightningFill size={20} className="text-white" />
                <h6 className="mb-0 text-white fw-bold">AI Analysis</h6>
                <small className="text-white-50 ms-2">Gemini AI</small>
              </div>
              <Button
                variant="outline-light"
                size="sm"
                onClick={handleAnalyze}
                disabled={isLoading}
                className="d-flex align-items-center gap-1"
              >
                <Lightning size={14} />
                Run again
              </Button>
            </div>
            <div className="ai-analysis-content">
              <ReactMarkdown
                remarkPlugins={[remarkGfm]}
                components={{
                  strong: ({ node, ...props }) => (
                    <span className="ai-analysis-strong" {...props} />
                  ),
                  p: ({ node, ...props }) => (
                    <p className="ai-analysis-paragraph" {...props} />
                  ),
                  ul: ({ node, ordered, ...props }) => (
                    <ul className="ai-analysis-list" {...props} />
                  ),
                  ol: ({ node, ...props }) => (
                    <ol className="ai-analysis-ordered-list" {...props} />
                  ),
                  li: ({ node, ordered, ...props }) => (
                    <li className="ai-analysis-list-item" {...props} />
                  ),
                  h2: ({ node, ...props }) => (
                    <h5 className="ai-analysis-heading" {...props} />
                  ),
                  h3: ({ node, ...props }) => (
                    <h6 className="ai-analysis-heading" {...props} />
                  ),
                  hr: () => <div className="ai-analysis-divider" />,
                }}
              >
                {analysis}
              </ReactMarkdown>
            </div>
          </div>
        )}
      </Card.Body>
    </Card>
  );
};

export default AIAnalysis;

