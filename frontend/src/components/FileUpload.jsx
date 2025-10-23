import React, { useRef, useState } from 'react';
import { Button, Spinner, Form } from 'react-bootstrap';
import { FileEarmarkArrowUp } from 'react-bootstrap-icons';

const FileUpload = ({ onFileUpload, isLoading }) => {
  const fileInputRef = useRef(null);
  const [isDragging, setIsDragging] = useState(false);

  const handleFileSelection = (file) => {
    if (!file || !onFileUpload) return;
    onFileUpload(file);
  };

  const handleFileChange = (event) => {
    const file = event.target.files?.[0];
    handleFileSelection(file);
    // reset value to allow reselecting same file
    event.target.value = '';
  };

  const handleButtonClick = () => {
    fileInputRef.current?.click();
  };

  const handleDragOver = (event) => {
    event.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (event) => {
    event.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = (event) => {
    event.preventDefault();
    setIsDragging(false);
    const file = event.dataTransfer.files?.[0];
    handleFileSelection(file);
  };

  return (
    <div
      className={`vt-upload-card text-center ${isDragging ? 'dragging' : ''}`}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
    >
      <div className="vt-upload-illustration mb-3">
        <FileEarmarkArrowUp size={80} />
      </div>
      <h5 className="vt-upload-title mb-2">Drag & drop or select suspicious file</h5>
      <p className="vt-upload-subtitle mb-4">
        File will be uploaded to VirusTotal for analysis. Maximum size 32 MB for free tier.
      </p>

      <div>
        <Button
          variant="primary"
          onClick={handleButtonClick}
          disabled={isLoading}
          className="vt-choose-file-btn"
        >
          {isLoading ? <Spinner as="span" animation="border" size="sm" /> : 'Choose File'}
        </Button>
      </div>

      <Form.Control type="file" ref={fileInputRef} onChange={handleFileChange} className="d-none" />
      <p className="vt-upload-disclaimer mt-4 mb-0">
        By uploading, you agree to share the sample with the security community according to VirusTotal's Terms of Service and Privacy Policy.
      </p>
    </div>
  );
};

export default FileUpload;
