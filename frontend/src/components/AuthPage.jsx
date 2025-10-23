import React, { useMemo, useState } from 'react';
import { Container, Row, Col, Card, Form, Button, InputGroup } from 'react-bootstrap';
import { ShieldLock, Person, Envelope, Lock, ArrowRight } from 'react-bootstrap-icons';

const USERS_STORAGE_KEY = 'vt-auth-users';

const safeParse = (value) => {
  try {
    return value ? JSON.parse(value) : [];
  } catch (error) {
    console.error('Failed to parse stored users', error);
    return [];
  }
};

const loadUsers = () => {
  if (typeof window === 'undefined') return [];
  return safeParse(window.localStorage.getItem(USERS_STORAGE_KEY));
};

const saveUsers = (users) => {
  if (typeof window === 'undefined') return;
  window.localStorage.setItem(USERS_STORAGE_KEY, JSON.stringify(users));
};

const defaultForm = {
  fullName: '',
  email: '',
  password: '',
  confirmPassword: '',
};

const AuthPage = ({ onSuccess }) => {
  const [mode, setMode] = useState('login');
  const [formValues, setFormValues] = useState(defaultForm);
  const [error, setError] = useState('');

  const isRegister = mode === 'register';

  const isValid = useMemo(() => {
    if (!formValues.email || !formValues.password) return false;
    if (isRegister) {
      if (!formValues.fullName || !formValues.confirmPassword) return false;
      if (formValues.password !== formValues.confirmPassword) return false;
    }
    return true;
  }, [formValues, isRegister]);

  const resetForm = (nextMode = mode) => {
    setFormValues(defaultForm);
    setMode(nextMode);
    setError('');
  };

  const handleChange = (field) => (event) => {
    setFormValues((prev) => ({ ...prev, [field]: event.target.value }));
  };

  const handleSubmit = (event) => {
    event.preventDefault();
    setError('');

    const users = loadUsers();

    if (isRegister) {
      const existed = users.find((user) => user.email.toLowerCase() === formValues.email.toLowerCase());
      if (existed) {
        setError('Email already exists. Please login or use a different email.');
        return;
      }

      const newUser = {
        fullName: formValues.fullName.trim(),
        email: formValues.email.trim().toLowerCase(),
        password: formValues.password,
      };

      users.push(newUser);
      saveUsers(users);
      onSuccess(newUser);
      resetForm('login');
      return;
    }

    const matchedUser = users.find(
      (user) =>
        user.email.toLowerCase() === formValues.email.trim().toLowerCase() &&
        user.password === formValues.password
    );

    if (!matchedUser) {
      setError('Invalid login credentials. Please check again.');
      return;
    }

    onSuccess(matchedUser);
    resetForm('login');
  };

  const toggleMode = () => {
    const nextMode = isRegister ? 'login' : 'register';
    resetForm(nextMode);
  };

  return (
    <div className="auth-page">
      <div className="auth-page__aurora aurora-a" />
      <div className="auth-page__aurora aurora-b" />
      <div className="auth-page__noise" />

      <Container className="auth-page__container">
        <Row className="justify-content-center align-items-center g-4">
          <Col lg={7} className="auth-hero">
            <div className="auth-hero__badge">
              <ShieldLock size={20} />
              <span>VirusTotal Intelligence</span>
            </div>
            <h1>
              Comprehensive Ransomware
              <br />
              <span>Analysis Center</span>
            </h1>
            <p>
              Scan hashes, URLs, domains, and IP addresses across 70+ antivirus engines. Login to sync your lookup history,
              receive real-time alerts, and build threat profiles for your organization.
            </p>
            <ul className="auth-hero__list">
              <li>Dashboard with detection metrics visualization</li>
              <li>Securely stored analysis records</li>
              <li>Quick sharing with incident response teams</li>
            </ul>
          </Col>

          <Col lg={5}>
            <Card className="auth-card glass-card border-0">
              <Card.Body className="p-4 pb-5">
                <div className="auth-card__header">
                  <h3>{isRegister ? 'Create New Account' : 'Welcome Back'}</h3>
                  <p>
                    {isRegister
                      ? 'Fill in your information to register and start analyzing ransomware data.'
                      : 'Login to continue analyzing threats for your organization.'}
                  </p>
                </div>

                <Form onSubmit={handleSubmit} className="auth-form">
                  {isRegister && (
                    <Form.Group className="mb-3" controlId="authFullName">
                      <Form.Label>Full Name</Form.Label>
                      <InputGroup>
                        <InputGroup.Text>
                          <Person size={18} />
                        </InputGroup.Text>
                        <Form.Control
                          type="text"
                          placeholder="John Doe"
                          value={formValues.fullName}
                          onChange={handleChange('fullName')}
                          required={isRegister}
                          className="vt-input"
                        />
                      </InputGroup>
                    </Form.Group>
                  )}

                  <Form.Group className="mb-3" controlId="authEmail">
                    <Form.Label>Email</Form.Label>
                    <InputGroup>
                      <InputGroup.Text>
                        <Envelope size={18} />
                      </InputGroup.Text>
                      <Form.Control
                        type="email"
                        placeholder="you@company.com"
                        value={formValues.email}
                        onChange={handleChange('email')}
                        required
                        className="vt-input"
                      />
                    </InputGroup>
                  </Form.Group>

                  <Form.Group className="mb-3" controlId="authPassword">
                    <Form.Label>Password</Form.Label>
                    <InputGroup>
                      <InputGroup.Text>
                        <Lock size={18} />
                      </InputGroup.Text>
                      <Form.Control
                        type="password"
                        placeholder="Enter password"
                        value={formValues.password}
                        onChange={handleChange('password')}
                        required
                        className="vt-input"
                      />
                    </InputGroup>
                  </Form.Group>

                  {isRegister && (
                    <Form.Group className="mb-3" controlId="authConfirmPassword">
                      <Form.Label>Confirm Password</Form.Label>
                      <InputGroup>
                        <InputGroup.Text>
                          <Lock size={18} />
                        </InputGroup.Text>
                        <Form.Control
                          type="password"
                          placeholder="Re-enter password"
                          value={formValues.confirmPassword}
                          onChange={handleChange('confirmPassword')}
                          required={isRegister}
                          className="vt-input"
                        />
                      </InputGroup>
                      {formValues.confirmPassword &&
                        formValues.confirmPassword !== formValues.password && (
                          <small className="text-warning d-block mt-2">Passwords do not match.</small>
                        )}
                    </Form.Group>
                  )}

                  {error && (
                    <div className="auth-error alert alert-danger py-2 px-3">
                      <small>{error}</small>
                    </div>
                  )}

                  <Button type="submit" variant="primary" size="lg" className="w-100 auth-submit mt-2" disabled={!isValid}>
                    {isRegister ? 'Register & Access' : 'Login'}
                    <ArrowRight size={18} className="ms-2" />
                  </Button>
                </Form>

                <div className="auth-card__footer">
                  {isRegister ? 'Already have an account?' : "Don't have an account?"}
                  <button type="button" className="auth-switch" onClick={toggleMode}>
                    {isRegister ? 'Login' : 'Create Account Now'}
                  </button>
                </div>
              </Card.Body>
            </Card>
          </Col>
        </Row>
      </Container>
    </div>
  );
};

export default AuthPage;
