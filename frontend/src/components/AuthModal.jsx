import React, { useState, useMemo } from 'react';
import { Modal, Form, Button, InputGroup } from 'react-bootstrap';
import { Envelope, Lock, Person, ShieldLock } from 'react-bootstrap-icons';

const initialForm = {
  fullName: '',
  email: '',
  password: '',
  confirmPassword: '',
};

const AuthModal = ({ show, mode, onClose, onSwitchMode }) => {
  const [formValues, setFormValues] = useState(initialForm);
  const [acceptedPolicy, setAcceptedPolicy] = useState(false);

  const isRegister = mode === 'register';

  const title = isRegister ? 'Create Secure Account' : 'Log in to Dashboard';
  const description = isRegister
    ? 'Create an account to sync analysis history, manage your team, and receive the latest ransomware alerts.'
    : 'Access your analysis dashboard to continue monitoring threats.';

  const isValid = useMemo(() => {
    if (!formValues.email || !formValues.password) return false;
    if (isRegister) {
      if (!formValues.fullName || !formValues.confirmPassword) return false;
      if (formValues.password !== formValues.confirmPassword) return false;
      if (!acceptedPolicy) return false;
    }
    return true;
  }, [formValues, isRegister, acceptedPolicy]);

  const handleChange = (field) => (event) => {
    setFormValues((prev) => ({ ...prev, [field]: event.target.value }));
  };

  const handleSubmit = (event) => {
    event.preventDefault();
    // Hiện tại chỉ giả lập; có thể tích hợp API sau
    const payload = { ...formValues, mode };
    console.table(payload);
    onClose();
    setFormValues(initialForm);
    setAcceptedPolicy(false);
  };

  const handleClose = () => {
    onClose();
    setFormValues(initialForm);
    setAcceptedPolicy(false);
  };

  return (
    <Modal show={show} onHide={handleClose} centered dialogClassName="auth-modal" contentClassName="auth-modal__content">
      <div className="auth-modal__header">
        <div className="auth-chip">
          <ShieldLock size={18} />
          <span>Secure Access</span>
        </div>
        <h2 className="auth-title">{title}</h2>
        <p className="auth-description">{description}</p>
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
              placeholder="ban@congty.com"
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
                placeholder="Confirm password"
                value={formValues.confirmPassword}
                onChange={handleChange('confirmPassword')}
                required={isRegister}
                className="vt-input"
              />
            </InputGroup>
            {formValues.confirmPassword && formValues.confirmPassword !== formValues.password && (
              <small className="text-danger d-block mt-2">Passwords do not match.</small>
            )}
          </Form.Group>
        )}

        {isRegister ? (
          <Form.Group className="mb-3" controlId="authPolicy">
            <Form.Check
              type="checkbox"
              label="I agree to the Terms of Service and Privacy Policy."
              checked={acceptedPolicy}
              onChange={(event) => setAcceptedPolicy(event.target.checked)}
            />
          </Form.Group>
        ) : (
          <div className="d-flex justify-content-end mb-3">
            <Button variant="link" className="auth-link">
              Forgot password?
            </Button>
          </div>
        )}

        <Button type="submit" variant="primary" size="lg" className="w-100 auth-submit" disabled={!isValid}>
          {isRegister ? 'Create Account' : 'Log in'}
        </Button>
      </Form>

      <div className="auth-footer">
        {isRegister ? (
          <p>
            Already have an account?{' '}
            <button type="button" className="auth-switch" onClick={() => onSwitchMode('login')}>
              Log in
            </button>
          </p>
        ) : (
          <p>
            Don't have an account?{' '}
            <button type="button" className="auth-switch" onClick={() => onSwitchMode('register')}>
              Create account now
            </button>
          </p>
        )}
      </div>
    </Modal>
  );
};

export default AuthModal;
