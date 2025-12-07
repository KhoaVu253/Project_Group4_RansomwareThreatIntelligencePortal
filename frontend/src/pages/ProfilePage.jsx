import React, { useEffect, useMemo, useState } from 'react';
import { Container, Row, Col, Card, Form, Button, Badge, Modal, Alert, Spinner, InputGroup } from 'react-bootstrap';
import { Eye, EyeSlash, Lock } from 'react-bootstrap-icons';
import axios from 'axios';

// Danh sách roles có sẵn
const AVAILABLE_ROLES = [
  { value: 'admin', label: 'Admin' },
  { value: 'analyst', label: 'Analyst' },
  { value: 'viewer', label: 'Viewer' },
];

const ProfilePage = ({
  user = {},
  profile = null,
  historyEntries = [],
  onUpdateProfile = () => {},
  backendBaseUrl = '',
}) => {
  const [isEditing, setIsEditing] = useState(false);
  const [showPasswordModal, setShowPasswordModal] = useState(false);
  const [passwordForm, setPasswordForm] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: '',
    otp: '',
  });
  const [passwordStep, setPasswordStep] = useState('request'); // 'request' | 'verify'
  const [passwordError, setPasswordError] = useState('');
  const [passwordSuccess, setPasswordSuccess] = useState('');
  const [isLoadingPassword, setIsLoadingPassword] = useState(false);
  const [isRequestingOTP, setIsRequestingOTP] = useState(false);
  const [showCurrentPassword, setShowCurrentPassword] = useState(false);
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isLoadingProfile, setIsLoadingProfile] = useState(false);
  
  // Ensure profile is always an object, not null
  const safeProfile = profile || {};
  
  const [formState, setFormState] = useState({
    displayName: safeProfile.displayName || user.fullName || user.email || '',
    email: safeProfile.email || user.email || '',
    organization: safeProfile.organization || '',
    role: user.role || safeProfile.role || 'analyst', // Role from user, not profile
    bio: safeProfile.bio || '',
  });

  useEffect(() => {
    const safeProfile = profile || {};
    setFormState({
      displayName: safeProfile.displayName || user.fullName || user.email || '',
      email: safeProfile.email || user.email || '',
      organization: safeProfile.organization || '',
      role: user.role || safeProfile.role || 'analyst', // Role from user
      bio: safeProfile.bio || '',
    });
  }, [profile, user]);
  
  // Load profile if not available
  useEffect(() => {
    if (!profile && user && user.email && backendBaseUrl) {
      setIsLoadingProfile(true);
      const loadProfile = async () => {
        try {
          const token = localStorage.getItem('vt-auth-token');
          if (!token) {
            setIsLoadingProfile(false);
            return;
          }
          
          const response = await axios.get(`${backendBaseUrl}/api/user/profile`, {
            headers: { Authorization: `Bearer ${token}` },
          });
          onUpdateProfile(response.data);
        } catch (err) {
          console.error('Failed to load profile', err);
          // Fallback: create default profile
          const defaultProfile = {
            displayName: user.fullName || user.email || 'User',
            email: user.email || '',
            organization: '',
            role: user.role || 'analyst',
            bio: '',
          };
          onUpdateProfile(defaultProfile);
        } finally {
          setIsLoadingProfile(false);
        }
      };
      loadProfile();
    }
  }, [profile, user, backendBaseUrl, onUpdateProfile]);

  const stats = useMemo(() => {
    const total = historyEntries?.length || 0;
    const malicious = historyEntries.filter((entry) => (entry?.malicious || 0) > 0).length;
    const suspicious = historyEntries.filter(
      (entry) => (entry?.malicious || 0) === 0 && (entry?.suspicious || 0) > 0
    ).length;
    const clean = total - malicious - suspicious;
    return { total, malicious, suspicious, clean };
  }, [historyEntries]);

  const handleChange = (field) => (event) => {
    const value = event.target.value;
    setFormState((prev) => ({ ...prev, [field]: value }));
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    setIsSubmitting(true);
    try {
      const token = localStorage.getItem('vt-auth-token');
      const response = await axios.put(
        `${backendBaseUrl}/api/user/profile`,
        {
          displayName: formState.displayName,
          organization: formState.organization,
          bio: formState.bio,
          // DO NOT send role - only admin can change role
        },
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      );
      onUpdateProfile(response.data);
    setIsEditing(false);
    } catch (err) {
      console.error('Failed to update profile', err);
      alert(err.response?.data?.error || 'Failed to update profile');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleRequestPasswordChangeOTP = async () => {
    setIsRequestingOTP(true);
    setPasswordError('');
    setPasswordSuccess('');
    try {
      const token = localStorage.getItem('vt-auth-token');
      if (!token) {
        setPasswordError('Please log in again. Token does not exist.');
        setIsRequestingOTP(false);
        return;
      }
      
      const response = await axios.post(
        `${backendBaseUrl}/api/user/change-password/request-otp`,
        {},
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      );
      setPasswordStep('verify');
      setPasswordSuccess('OTP has been sent to your email. Please check your inbox.');
    } catch (err) {
      console.error('Failed to request OTP:', err);
      const errorMessage = err.response?.data?.error || err.message || 'Unable to send OTP';
      
      // Handle specific error cases
      if (err.response?.status === 401) {
        setPasswordError('Token has expired. Please log in again.');
        // Auto redirect or clear token
        setTimeout(() => {
          localStorage.removeItem('vt-auth-token');
          localStorage.removeItem('vt-auth-user');
          window.location.reload();
        }, 2000);
      } else if (err.response?.status === 500) {
        // Use detailed error message from backend if available
        const backendError = err.response?.data?.error || 'Server error while sending email. Please try again later.';
        setPasswordError(backendError);
      } else {
        setPasswordError(errorMessage);
      }
    } finally {
      setIsRequestingOTP(false);
    }
  };

  const handleChangePassword = async (e) => {
    e.preventDefault();
    setPasswordError('');
    
    if (passwordForm.newPassword !== passwordForm.confirmPassword) {
      setPasswordError('New password and confirmation do not match');
      return;
    }
    
    setIsLoadingPassword(true);
    try {
      const token = localStorage.getItem('vt-auth-token');
      const response = await axios.post(
        `${backendBaseUrl}/api/user/change-password`,
        {
          otp: passwordForm.otp,
          newPassword: passwordForm.newPassword,
          currentPassword: passwordForm.currentPassword || undefined, // Optional
        },
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      );
      setPasswordSuccess('Password changed successfully');
      setTimeout(() => {
        setShowPasswordModal(false);
        setPasswordForm({
          currentPassword: '',
          newPassword: '',
          confirmPassword: '',
          otp: '',
        });
        setPasswordStep('request');
        setPasswordError('');
        setPasswordSuccess('');
      }, 2000);
    } catch (err) {
      setPasswordError(err.response?.data?.error || 'Failed to change password');
    } finally {
      setIsLoadingPassword(false);
    }
  };

  const handleClosePasswordModal = () => {
    setShowPasswordModal(false);
    setPasswordForm({
      currentPassword: '',
      newPassword: '',
      confirmPassword: '',
      otp: '',
    });
    setPasswordStep('request');
    setPasswordError('');
    setPasswordSuccess('');
  };

  const handleReset = () => {
    const safeProfile = profile || {};
    setFormState({
      displayName: safeProfile.displayName || user.fullName || user.email || '',
      email: safeProfile.email || user.email || '',
      organization: safeProfile.organization || '',
      role: user.role || safeProfile.role || 'analyst',
      bio: safeProfile.bio || '',
    });
    setIsEditing(false);
  };

  const displayName = formState.displayName || user.fullName || user.email || 'User';
  const email = formState.email || user.email || 'N/A';

  // Show loading if profile is being loaded
  if (isLoadingProfile && !profile) {
    return (
      <Container className="profile-page py-5">
        <div className="d-flex justify-content-center align-items-center" style={{ minHeight: '400px' }}>
          <div className="text-center">
            <Spinner animation="border" variant="primary" className="mb-3" style={{ width: '3rem', height: '3rem' }} />
            <p className="text-muted">Loading profile...</p>
          </div>
        </div>
      </Container>
    );
  }

  return (
    <Container className="profile-page py-5">
      <Row className="g-4">
        <Col lg={4}>
          <Card className="glass-card profile-card h-100">
            <Card.Body>
              <div className="d-flex flex-column align-items-center text-center">
                <div className="profile-avatar mb-3">
                  {displayName
                    .split(' ')
                    .map((part) => part[0])
                    .join('')
                    .slice(0, 2)
                    .toUpperCase()}
                </div>
                <h4 className="mb-1">{displayName}</h4>
                <p className="text-muted mb-2">{email}</p>
                {formState.organization && (
                  <Badge bg="primary" className="mb-2">
                    {formState.organization}
                  </Badge>
                )}
                {formState.role && <p className="text-muted mb-3">Role: {AVAILABLE_ROLES.find(r => r.value === formState.role)?.label || formState.role}</p>}
                {formState.bio && <p className="profile-bio">{formState.bio}</p>}
                <div className="d-flex gap-2 mt-3">
                  <Button size="sm" variant="outline-light" onClick={() => setIsEditing(true)}>
                    Edit Profile
                  </Button>
                  <Button 
                    size="sm" 
                    variant="outline-warning" 
                    onClick={() => setShowPasswordModal(true)}
                  >
                    Change Password
                  </Button>
                </div>
              </div>
            </Card.Body>
          </Card>
        </Col>
        <Col lg={8}>
          <Row className="g-3 mb-4">
            <Col md={4}>
              <Card className="glass-card profile-stat-card">
                <Card.Body>
                  <h6 className="text-muted text-uppercase mb-2">Total Scans</h6>
                  <span className="profile-stat-value">{stats.total}</span>
                </Card.Body>
              </Card>
            </Col>
            <Col md={4}>
              <Card className="glass-card profile-stat-card">
                <Card.Body>
                  <h6 className="text-muted text-uppercase mb-2">Malicious</h6>
                  <span className="profile-stat-value text-danger">{stats.malicious}</span>
                </Card.Body>
              </Card>
            </Col>
            <Col md={4}>
              <Card className="glass-card profile-stat-card">
                <Card.Body>
                  <h6 className="text-muted text-uppercase mb-2">Suspicious</h6>
                  <span className="profile-stat-value text-warning">{stats.suspicious}</span>
                </Card.Body>
              </Card>
            </Col>
          </Row>
          <Card className="glass-card">
            <Card.Header>
              <h5 className="mb-0">Personal Information</h5>
            </Card.Header>
            <Card.Body>
              <Form onSubmit={handleSubmit}>
                <Row className="g-3">
                  <Col md={6}>
                    <Form.Group controlId="profileDisplayName">
                      <Form.Label>Display Name</Form.Label>
                      <Form.Control
                        className="vt-input"
                        type="text"
                        value={formState.displayName || ''}
                        onChange={handleChange('displayName')}
                        disabled={!isEditing}
                      />
                    </Form.Group>
                  </Col>
                  <Col md={6}>
                    <Form.Group controlId="profileEmail">
                      <Form.Label>Email</Form.Label>
                      <Form.Control className="vt-input" type="email" value={email} disabled readOnly />
                    </Form.Group>
                  </Col>
                  <Col md={6}>
                    <Form.Group controlId="profileOrganization">
                      <Form.Label>Organization</Form.Label>
                      <Form.Control
                        className="vt-input"
                        type="text"
                        value={formState.organization || ''}
                        onChange={handleChange('organization')}
                        disabled={!isEditing}
                      />
                    </Form.Group>
                  </Col>
                  <Col md={6}>
                    <Form.Group controlId="profileRole">
                      <Form.Label>Role</Form.Label>
                      <Form.Select
                        className="vt-input"
                        value={formState.role || 'analyst'}
                        disabled={true} // Role is read-only, cannot be edited
                        style={{ opacity: 0.7, cursor: 'not-allowed' }}
                      >
                        {AVAILABLE_ROLES.map((role) => (
                          <option key={role.value} value={role.value}>
                            {role.label}
                          </option>
                        ))}
                      </Form.Select>
                      <Form.Text className="text-muted">
                        Role can only be changed by admin
                      </Form.Text>
                    </Form.Group>
                  </Col>
                  <Col xs={12}>
                    <Form.Group controlId="profileBio">
                      <Form.Label>Short Note</Form.Label>
                      <Form.Control
                        as="textarea"
                        rows={3}
                        className="vt-input"
                        value={formState.bio || ''}
                        onChange={handleChange('bio')}
                        disabled={!isEditing}
                      />
                    </Form.Group>
                  </Col>
                </Row>
                <div className="d-flex justify-content-end gap-2 mt-4">
                  {!isEditing ? (
                    <Button variant="primary" onClick={() => setIsEditing(true)}>
                      Edit
                    </Button>
                  ) : (
                    <>
                      <Button variant="outline-light" onClick={handleReset}>
                        Cancel
                      </Button>
                      <Button type="submit" variant="primary" disabled={isSubmitting}>
                        {isSubmitting ? 'Saving...' : 'Save Changes'}
                      </Button>
                    </>
                  )}
                </div>
              </Form>
            </Card.Body>
          </Card>
        </Col>
      </Row>

      {/* Password Change Modal */}
      <Modal 
        show={showPasswordModal} 
        onHide={handleClosePasswordModal} 
        centered
        className="password-change-modal"
        contentClassName="password-change-modal-content"
      >
        <Modal.Header closeButton className="password-change-modal-header">
          <Modal.Title>Change Password</Modal.Title>
        </Modal.Header>
        <Modal.Body className="password-change-modal-body">
          {passwordSuccess && <Alert variant="success">{passwordSuccess}</Alert>}
          {passwordError && <Alert variant="danger">{passwordError}</Alert>}
          
          {passwordStep === 'request' ? (
            <div className="text-center py-3">
              <p>You need to verify with an OTP to change your password. An OTP will be sent to your email.</p>
              <Button 
                variant="primary" 
                onClick={handleRequestPasswordChangeOTP}
                disabled={isRequestingOTP}
              >
                {isRequestingOTP ? (
                  <>
                    <Spinner as="span" animation="border" size="sm" role="status" aria-hidden="true" className="me-2" />
                    Sending...
                  </>
                ) : (
                  'Send OTP'
                )}
              </Button>
            </div>
          ) : (
            <Form onSubmit={handleChangePassword}>
              <Form.Group className="mb-3">
                <Form.Label>Current Password (Optional)</Form.Label>
                <InputGroup>
                  <InputGroup.Text>
                    <Lock size={18} />
                  </InputGroup.Text>
                  <Form.Control
                    type={showCurrentPassword ? "text" : "password"}
                    value={passwordForm.currentPassword}
                    onChange={(e) => setPasswordForm({...passwordForm, currentPassword: e.target.value})}
                    placeholder="Enter current password (optional)"
                    className="vt-input"
                  />
                  <Button
                    variant="outline-secondary"
                    onClick={() => setShowCurrentPassword(!showCurrentPassword)}
                    type="button"
                  >
                    {showCurrentPassword ? <EyeSlash size={18} /> : <Eye size={18} />}
                  </Button>
                </InputGroup>
              </Form.Group>
              
              <Form.Group className="mb-3">
                <Form.Label>OTP Code</Form.Label>
                <Form.Control
                  type="text"
                  value={passwordForm.otp}
                  onChange={(e) => setPasswordForm({...passwordForm, otp: e.target.value})}
                  placeholder="Enter OTP code from email"
                  maxLength={6}
                  required
                  className="vt-input"
                />
              </Form.Group>
              
              <Form.Group className="mb-3">
                <Form.Label>New Password</Form.Label>
                <InputGroup>
                  <InputGroup.Text>
                    <Lock size={18} />
                  </InputGroup.Text>
                  <Form.Control
                    type={showNewPassword ? "text" : "password"}
                    value={passwordForm.newPassword}
                    onChange={(e) => setPasswordForm({...passwordForm, newPassword: e.target.value})}
                    placeholder="New password"
                    required
                    className="vt-input"
                  />
                  <Button
                    variant="outline-secondary"
                    onClick={() => setShowNewPassword(!showNewPassword)}
                    type="button"
                  >
                    {showNewPassword ? <EyeSlash size={18} /> : <Eye size={18} />}
                  </Button>
                </InputGroup>
              </Form.Group>
              
              <Form.Group className="mb-3">
                <Form.Label>Confirm New Password</Form.Label>
                <InputGroup>
                  <InputGroup.Text>
                    <Lock size={18} />
                  </InputGroup.Text>
                  <Form.Control
                    type={showConfirmPassword ? "text" : "password"}
                    value={passwordForm.confirmPassword}
                    onChange={(e) => setPasswordForm({...passwordForm, confirmPassword: e.target.value})}
                    placeholder="Confirm new password"
                    required
                    className="vt-input"
                  />
                  <Button
                    variant="outline-secondary"
                    onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                    type="button"
                  >
                    {showConfirmPassword ? <EyeSlash size={18} /> : <Eye size={18} />}
                  </Button>
                </InputGroup>
              </Form.Group>
              
              <div className="d-flex justify-content-end gap-2">
                <Button variant="outline-secondary" onClick={handleClosePasswordModal}>
                  Cancel
                </Button>
                <Button type="submit" variant="primary" disabled={isLoadingPassword}>
                  {isLoadingPassword ? (
                    <>
                      <Spinner as="span" animation="border" size="sm" role="status" aria-hidden="true" className="me-2" />
                      Processing...
                    </>
                  ) : (
                    'Change Password'
                  )}
                </Button>
              </div>
            </Form>
          )}
        </Modal.Body>
      </Modal>
    </Container>
  );
};

export default ProfilePage;
