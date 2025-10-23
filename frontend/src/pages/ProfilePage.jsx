import React, { useEffect, useMemo, useState } from 'react';
import { Container, Row, Col, Card, Form, Button, Badge } from 'react-bootstrap';

const ProfilePage = ({
  user = {},
  profile = {},
  historyEntries = [],
  onUpdateProfile = () => {},
}) => {
  const [isEditing, setIsEditing] = useState(false);
  const [formState, setFormState] = useState({
    displayName: profile.displayName || user.fullName || user.email || '',
    email: profile.email || user.email || '',
    organization: profile.organization || '',
    role: profile.role || '',
    bio: profile.bio || '',
  });

  useEffect(() => {
    setFormState({
      displayName: profile.displayName || user.fullName || user.email || '',
      email: profile.email || user.email || '',
      organization: profile.organization || '',
      role: profile.role || '',
      bio: profile.bio || '',
    });
  }, [profile, user]);

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

  const handleSubmit = (event) => {
    event.preventDefault();
    onUpdateProfile(formState);
    setIsEditing(false);
  };

  const handleReset = () => {
    setFormState({
      displayName: profile.displayName || user.fullName || user.email || '',
      email: profile.email || user.email || '',
      organization: profile.organization || '',
      role: profile.role || '',
      bio: profile.bio || '',
    });
    setIsEditing(false);
  };

  const displayName = formState.displayName || user.fullName || user.email || 'User';
  const email = formState.email || user.email || 'N/A';

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
                {formState.role && <p className="text-muted mb-3">Role: {formState.role}</p>}
                {formState.bio && <p className="profile-bio">{formState.bio}</p>}
                <div className="d-flex gap-2 mt-3">
                  <Button size="sm" variant="outline-light" onClick={() => setIsEditing(true)}>
                    Edit Profile
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
                      <Form.Control
                        className="vt-input"
                        type="text"
                        value={formState.role || ''}
                        onChange={handleChange('role')}
                        disabled={!isEditing}
                      />
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
                      <Button type="submit" variant="primary">
                        Save Changes
                      </Button>
                    </>
                  )}
                </div>
              </Form>
            </Card.Body>
          </Card>
        </Col>
      </Row>
    </Container>
  );
};

export default ProfilePage;
