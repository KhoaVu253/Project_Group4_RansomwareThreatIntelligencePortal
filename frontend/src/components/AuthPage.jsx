import React, { useMemo, useState, useEffect, useRef } from 'react';
import { Container, Row, Col, Card, Form, Button, InputGroup, ProgressBar, Modal, Alert } from 'react-bootstrap';
import { ShieldLock, Person, Envelope, Lock, ArrowRight, Eye, EyeSlash } from 'react-bootstrap-icons';
import axios from 'axios';
import { validatePassword } from '../utils/passwordValidator';

const defaultForm = {
  fullName: '',
  email: '',
  password: '',
  confirmPassword: '',
  twoFactorToken: '',
  otp: '',
  resetOtp: '',
  resetEmail: '',
  resetNewPassword: '',
  resetConfirmPassword: '',
  captchaToken: '',
};

const AuthPage = ({ onSuccess }) => {
  const [mode, setMode] = useState('login');
  const [formValues, setFormValues] = useState(defaultForm);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [passwordStrength, setPasswordStrength] = useState(null);
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [requires2FA, setRequires2FA] = useState(false);
  const [requiresOtp, setRequiresOtp] = useState(false);
  const [otpExpiresIn, setOtpExpiresIn] = useState(null);
  const [showVerificationModal, setShowVerificationModal] = useState(false);
  const [verificationEmail, setVerificationEmail] = useState('');
  const [isResettingPassword, setIsResettingPassword] = useState(false);
  const [requiresResetOtp, setRequiresResetOtp] = useState(false);
  const [requiresCaptcha, setRequiresCaptcha] = useState(false);
  const [captchaReady, setCaptchaReady] = useState(false);
  const [captchaWidgetId, setCaptchaWidgetId] = useState(null);
  const recaptchaSiteKey = import.meta.env.VITE_RECAPTCHA_SITE_KEY || '';
  const captchaRef = useRef(null);
  // CAPTCHA for registration
  const [captchaWidgetIdRegister, setCaptchaWidgetIdRegister] = useState(null);
  const captchaRefRegister = useRef(null);

  const isRegister = mode === 'register';

  const backendBaseUrl = useMemo(() => {
    const raw = import.meta.env.VITE_BACKEND_URL || '';
    return raw.endsWith('/') ? raw.slice(0, -1) : raw;
  }, []);

  const isValid = useMemo(() => {
    if (isResettingPassword) {
      if (!formValues.resetEmail) return false;
      if (requiresResetOtp) {
        if (!formValues.resetOtp) return false;
        if (!formValues.resetNewPassword || formValues.resetNewPassword !== formValues.resetConfirmPassword) return false;
      }
      return true;
    }

    if (!formValues.email || !formValues.password) return false;
    if (isRegister) {
      if (!formValues.fullName || !formValues.confirmPassword) return false;
      if (formValues.password !== formValues.confirmPassword) return false;
      if (passwordStrength && !passwordStrength.isValid) return false;
      if (requiresOtp && !formValues.otp) return false;
      // Require CAPTCHA when registering (before OTP step) if site key is configured
      if (recaptchaSiteKey && !requiresOtp && !formValues.captchaToken) return false;
    }
    if (requires2FA && !formValues.twoFactorToken) return false;
    if (requiresCaptcha && !formValues.captchaToken) return false;
    return true;
  }, [formValues, isRegister, passwordStrength, requires2FA, requiresOtp, isResettingPassword, requiresResetOtp, requiresCaptcha, recaptchaSiteKey]);

  const resetForm = (nextMode = mode) => {
    setFormValues(defaultForm);
    setMode(nextMode);
    setError('');
    setSuccess('');
    setPasswordStrength(null);
    setRequires2FA(false);
    setRequiresOtp(false);
    setOtpExpiresIn(null);
    setShowVerificationModal(false);
    setIsResettingPassword(false);
    setRequiresResetOtp(false);
    setRequiresCaptcha(false);
    // Ensure the existing widget is fully reset before clearing state
    if (captchaWidgetId !== null && window.grecaptcha) {
      try {
        window.grecaptcha.reset(captchaWidgetId);
      } catch (err) {
        console.error('Failed to reset reCAPTCHA during form reset:', err);
      }
    }
    setCaptchaWidgetId(null);
    if (captchaRef.current) {
      captchaRef.current.innerHTML = '';
    }
    // Reset CAPTCHA for registration
    if (captchaWidgetIdRegister !== null && window.grecaptcha) {
      try {
        window.grecaptcha.reset(captchaWidgetIdRegister);
      } catch (err) {
        console.error('Failed to reset reCAPTCHA for registration during form reset:', err);
      }
    }
    setCaptchaWidgetIdRegister(null);
    if (captchaRefRegister.current) {
      captchaRefRegister.current.innerHTML = '';
    }
  };

  const handleChange = (field) => (event) => {
    setFormValues((prev) => ({ ...prev, [field]: event.target.value }));
  };

  const handlePasswordChange = (event) => {
    const password = event.target.value;
    setFormValues((prev) => ({ ...prev, password }));
    
    if (isRegister && password) {
      const validation = validatePassword(password);
      setPasswordStrength(validation);
    } else {
      setPasswordStrength(null);
    }
  };

  // Load reCAPTCHA v2 script if site key is provided
  useEffect(() => {
    if (!recaptchaSiteKey || recaptchaSiteKey.trim().length === 0) {
      setCaptchaReady(false);
      return;
    }
    
    const scriptId = 'recaptcha-script';
    const existing = document.getElementById(scriptId);
    
    if (existing) {
      if (window.grecaptcha) {
        setCaptchaReady(true);
      }
      return;
    }

    const script = document.createElement('script');
    script.id = scriptId;
    // v2 doesn't use render parameter
    script.src = `https://www.google.com/recaptcha/api.js`;
    script.async = true;
    script.defer = true;
    script.onload = () => {
      if (window.grecaptcha) {
        window.grecaptcha.ready(() => {
          setCaptchaReady(true);
          console.log('reCAPTCHA v2 loaded successfully');
        });
      }
    };
    script.onerror = () => {
      setCaptchaReady(false);
      console.error('Failed to load reCAPTCHA script');
    };
    document.body.appendChild(script);
  }, [recaptchaSiteKey]);

  // Render reCAPTCHA v2 checkbox when required
  useEffect(() => {
    // widgetId can be 0, so check for null explicitly
    if (requiresCaptcha && captchaReady && recaptchaSiteKey && captchaRef.current && captchaWidgetId === null) {
      // Clear any existing content
      captchaRef.current.innerHTML = '';
      
      try {
        const widgetId = window.grecaptcha.render(captchaRef.current, {
          'sitekey': recaptchaSiteKey,
          'callback': (token) => {
            console.log('reCAPTCHA v2 token received');
            setFormValues((prev) => ({ ...prev, captchaToken: token }));
            setSuccess('CAPTCHA verified. Click Login to finish signing in.');
          },
          'expired-callback': () => {
            console.log('reCAPTCHA v2 token expired');
            setFormValues((prev) => ({ ...prev, captchaToken: '' }));
            setError('CAPTCHA expired. Please verify again.');
          },
          'error-callback': () => {
            console.error('reCAPTCHA v2 error');
            setFormValues((prev) => ({ ...prev, captchaToken: '' }));
            setError('CAPTCHA error. Please try again.');
          }
        });
        setCaptchaWidgetId(widgetId);
        console.log('reCAPTCHA v2 widget rendered with ID:', widgetId);
      } catch (err) {
        console.error('Failed to render reCAPTCHA v2:', err);
        setError('Could not load CAPTCHA. Please refresh the page and try again.');
      }
    }

    // Cleanup: reset widget when not required
    if (!requiresCaptcha && captchaWidgetId !== null) {
      if (window.grecaptcha && captchaWidgetId !== null) {
        try {
          window.grecaptcha.reset(captchaWidgetId);
        } catch (err) {
          console.error('Failed to reset reCAPTCHA:', err);
        }
      }
      setCaptchaWidgetId(null);
      if (captchaRef.current) {
        captchaRef.current.innerHTML = '';
      }
      setFormValues((prev) => ({ ...prev, captchaToken: '' }));
    }
  }, [requiresCaptcha, captchaReady, recaptchaSiteKey, captchaWidgetId]);

  // Render reCAPTCHA v2 for registration form
  useEffect(() => {
    // Only render when in register mode, before OTP step, and site key is configured
    if (isRegister && !requiresOtp && recaptchaSiteKey && captchaReady && captchaRefRegister.current && captchaWidgetIdRegister === null) {
      captchaRefRegister.current.innerHTML = '';
      
      try {
        const widgetId = window.grecaptcha.render(captchaRefRegister.current, {
          'sitekey': recaptchaSiteKey,
          'callback': (token) => {
            console.log('reCAPTCHA v2 token received for registration');
            setFormValues((prev) => ({ ...prev, captchaToken: token }));
          },
          'expired-callback': () => {
            console.log('reCAPTCHA v2 token expired for registration');
            setFormValues((prev) => ({ ...prev, captchaToken: '' }));
            setError('CAPTCHA expired. Please verify again.');
          },
          'error-callback': () => {
            console.error('reCAPTCHA v2 error for registration');
            setFormValues((prev) => ({ ...prev, captchaToken: '' }));
            setError('CAPTCHA error. Please try again.');
          }
        });
        setCaptchaWidgetIdRegister(widgetId);
        console.log('reCAPTCHA v2 widget rendered for registration with ID:', widgetId);
      } catch (err) {
        console.error('Failed to render reCAPTCHA v2 for registration:', err);
        setError('Could not load CAPTCHA. Please refresh the page and try again.');
      }
    }

    // Cleanup: reset widget when not in register mode or when OTP is required
    if ((!isRegister || requiresOtp) && captchaWidgetIdRegister !== null) {
      if (window.grecaptcha && captchaWidgetIdRegister !== null) {
        try {
          window.grecaptcha.reset(captchaWidgetIdRegister);
        } catch (err) {
          console.error('Failed to reset reCAPTCHA for registration:', err);
        }
      }
      setCaptchaWidgetIdRegister(null);
      if (captchaRefRegister.current) {
        captchaRefRegister.current.innerHTML = '';
      }
      // Don't clear captchaToken here as it might be needed for the request
    }
  }, [isRegister, requiresOtp, captchaReady, recaptchaSiteKey, captchaWidgetIdRegister]);


  const handleSubmit = async (event) => {
    event.preventDefault();
    setError('');
    setSuccess('');
    setLoading(true);

    try {
      const apiUrl = backendBaseUrl || '';

      if (isResettingPassword) {
        if (!requiresResetOtp) {
          // Step 1: request OTP
          await axios.post(`${apiUrl}/api/auth/forgot-password`, {
            email: formValues.resetEmail.trim().toLowerCase(),
          });
          setRequiresResetOtp(true);
          setSuccess('OTP has been sent to your email. Please check and enter it below.');
          setError('');
          setLoading(false);
          return;
        }
        // Step 2: submit OTP + new password
        if (formValues.resetNewPassword !== formValues.resetConfirmPassword) {
          setError('Passwords do not match');
          setLoading(false);
          return;
        }
        await axios.post(`${apiUrl}/api/auth/reset-password`, {
          email: formValues.resetEmail.trim().toLowerCase(),
          otp: formValues.resetOtp.trim(),
          new_password: formValues.resetNewPassword,
        });
        setSuccess('Password has been reset. You can log in now.');
        setError('');
        setIsResettingPassword(false);
        setRequiresResetOtp(false);
        setFormValues(defaultForm);
        setMode('login');
        setLoading(false);
        return;
      }

      if (isRegister) {
        // Validate password match
        if (formValues.password !== formValues.confirmPassword) {
          setError('Passwords do not match');
          setLoading(false);
          return;
        }

        // Validate password strength
        if (passwordStrength && !passwordStrength.isValid) {
          setError('Password is not strong enough. Please check the requirements below.');
          setLoading(false);
          return;
        }

        // Build payload; include OTP if we are in step 2, include CAPTCHA if in step 1
        const payload = {
          email: formValues.email.trim().toLowerCase(),
          password: formValues.password,
          fullName: formValues.fullName.trim(),
        };

        if (requiresOtp) {
          payload.otp = formValues.otp.trim();
        } else {
          // Send CAPTCHA token when registering first time (before OTP)
          if (recaptchaSiteKey && formValues.captchaToken) {
            payload.captcha_token = formValues.captchaToken;
          }
        }

        const response = await axios.post(`${apiUrl}/api/auth/register`, payload);

        if (response.status === 201) {
          setSuccess('Registration successful! You can log in now.');
          resetForm('login');
          return;
        }

        // OTP step required
        if (response.data?.requires_otp) {
          setRequiresOtp(true);
          setOtpExpiresIn(response.data?.otp_expires_in || null);
          setSuccess('OTP has been sent to your email. Enter it to finish registration.');
          setError('');
          return;
        }
      } else {
        // Login
        const loginData = {
          email: formValues.email.trim().toLowerCase(),
          password: formValues.password,
        };

        if (requires2FA) {
          loginData.two_factor_token = formValues.twoFactorToken;
        }

        // Add captcha token if required
        if (requiresCaptcha && formValues.captchaToken) {
          loginData.captcha_token = formValues.captchaToken;
        }

        const response = await axios.post(`${apiUrl}/api/auth/login`, loginData);

        if (response.data.requires_2fa) {
          setRequires2FA(true);
          setError('');
          setLoading(false);
          return;
        }

        // Check if CAPTCHA is required (password is correct)
        if (response.data.requires_captcha) {
          setRequiresCaptcha(true);
          setError('');
          setLoading(false);
          // CAPTCHA v2 widget will be rendered by useEffect
          return;
        }

        // If CAPTCHA verification failed, reset widget
        if (response.status === 400 && response.data.error && response.data.error.toLowerCase().includes('captcha')) {
          if (captchaWidgetId !== null && window.grecaptcha) {
            try {
              window.grecaptcha.reset(captchaWidgetId);
              setFormValues((prev) => ({ ...prev, captchaToken: '' }));
            } catch (err) {
              console.error('Failed to reset CAPTCHA:', err);
            }
          }
        }

        if (response.data.access_token) {
          // Store token and user data
          const userData = {
            id: response.data.user.id,
            email: response.data.user.email,
            fullName: response.data.user.fullName,
            accessToken: response.data.access_token,
            twoFactorEnabled: response.data.user.twoFactorEnabled,
          };

          localStorage.setItem('vt-auth-user', JSON.stringify(userData));
          localStorage.setItem('vt-auth-token', response.data.access_token);

          onSuccess(userData);
          resetForm('login');
        }
      }
    } catch (err) {
      const data = err.response?.data || {};
      const status = err.response?.status;
      if (data.requires_reset) {
        setError('You entered the wrong password more than 5 times. Please reset your password with the OTP sent to your email.');
      } else if (status === 401) {
        const remaining = typeof data.remaining_attempts === 'number' ? data.remaining_attempts : null;
        if (remaining !== null) {
          setError(`Email or password is incorrect. You have ${remaining} attempt${remaining === 1 ? '' : 's'} left.`);
        } else {
          setError('Email or password is incorrect. You can retry up to 5 times.');
        }
      } else {
        const errorMessage = data.error || err.message || 'An error occurred';
        setError(errorMessage);
      }
      
      if (err.response?.data?.requires_verification) {
        setVerificationEmail(formValues.email);
        setShowVerificationModal(true);
      }
    } finally {
      setLoading(false);
    }
  };

  const handleResendVerification = async () => {
    if (!verificationEmail) return;
    
    setLoading(true);
    try {
      const apiUrl = backendBaseUrl || '';
      await axios.post(`${apiUrl}/api/auth/resend-verification`, {
        email: verificationEmail,
      });
      setSuccess('Verification email resent!');
      setError('');
    } catch (err) {
      setError(err.response?.data?.error || 'Could not resend email');
    } finally {
      setLoading(false);
    }
  };

  const toggleMode = () => {
    const nextMode = isRegister ? 'login' : 'register';
    resetForm(nextMode);
  };

  return (
    <>
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
                    {isResettingPassword ? (
                      <>
                        <Form.Group className="mb-3" controlId="resetEmail">
                          <Form.Label>Reset Email</Form.Label>
                          <InputGroup>
                            <InputGroup.Text>
                              <Envelope size={18} />
                            </InputGroup.Text>
                            <Form.Control
                              type="email"
                              placeholder="you@company.com"
                              value={formValues.resetEmail}
                              onChange={handleChange('resetEmail')}
                              required
                              className="vt-input"
                            />
                          </InputGroup>
                        </Form.Group>

                        {requiresResetOtp && (
                          <>
                            <Form.Group className="mb-3" controlId="resetOtp">
                              <Form.Label>OTP Code</Form.Label>
                              <InputGroup>
                                <InputGroup.Text>
                                  <ShieldLock size={18} />
                                </InputGroup.Text>
                                <Form.Control
                                  type="text"
                                  placeholder="Enter 6-digit OTP"
                                  value={formValues.resetOtp}
                                  onChange={handleChange('resetOtp')}
                                  required
                                  className="vt-input"
                                  maxLength={6}
                                />
                              </InputGroup>
                            </Form.Group>

                            <Form.Group className="mb-3" controlId="resetNewPassword">
                              <Form.Label>New Password</Form.Label>
                              <InputGroup>
                                <InputGroup.Text>
                                  <Lock size={18} />
                                </InputGroup.Text>
                                <Form.Control
                                  type={showPassword ? "text" : "password"}
                                  placeholder="Enter new password"
                                  value={formValues.resetNewPassword}
                                  onChange={handleChange('resetNewPassword')}
                                  required
                                  className="vt-input"
                                />
                              </InputGroup>
                            </Form.Group>

                            <Form.Group className="mb-3" controlId="resetConfirmPassword">
                              <Form.Label>Confirm New Password</Form.Label>
                              <InputGroup>
                                <InputGroup.Text>
                                  <Lock size={18} />
                                </InputGroup.Text>
                                <Form.Control
                                  type={showPassword ? "text" : "password"}
                                  placeholder="Re-enter new password"
                                  value={formValues.resetConfirmPassword}
                                  onChange={handleChange('resetConfirmPassword')}
                                  required
                                  className="vt-input"
                                />
                              </InputGroup>
                              {formValues.resetConfirmPassword && formValues.resetNewPassword !== formValues.resetConfirmPassword && (
                                <small className="text-danger">Passwords do not match</small>
                              )}
                            </Form.Group>
                          </>
                        )}
                      </>
                    ) : (
                      <>
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
                          type={showPassword ? "text" : "password"}
                          placeholder="Enter password"
                          value={formValues.password}
                          onChange={handlePasswordChange}
                          required
                          className="vt-input"
                        />
                        <Button
                          variant="outline-secondary"
                          onClick={() => setShowPassword(!showPassword)}
                          type="button"
                        >
                          {showPassword ? <EyeSlash size={18} /> : <Eye size={18} />}
                        </Button>
                      </InputGroup>
                      
                      {isRegister && passwordStrength && (
                        <div className="mt-2">
                          <ProgressBar
                            now={(passwordStrength.score / 6) * 100}
                            variant={
                              passwordStrength.strength === 'strong' ? 'success' :
                              passwordStrength.strength === 'medium' ? 'warning' : 'danger'
                            }
                            className="mb-2"
                          />
                          <small className={`d-block mb-1 ${
                            passwordStrength.strength === 'strong' ? 'text-success' :
                            passwordStrength.strength === 'medium' ? 'text-warning' : 'text-danger'
                          }`}>
                            Strength: {passwordStrength.strength === 'strong' ? 'Strong' :
                                       passwordStrength.strength === 'medium' ? 'Medium' : 'Weak'}
                          </small>
                          {passwordStrength.errors.length > 0 && (
                            <ul className="list-unstyled mt-1 mb-0 small">
                              {passwordStrength.errors.map((err, idx) => (
                                <li key={idx} className="text-danger">
                                  • {err}
                                </li>
                              ))}
                            </ul>
                          )}
                        </div>
                      )}
                    </Form.Group>

                    {isRegister && (
                      <Form.Group className="mb-3" controlId="authConfirmPassword">
                        <Form.Label>Confirm Password</Form.Label>
                        <InputGroup>
                          <InputGroup.Text>
                            <Lock size={18} />
                          </InputGroup.Text>
                          <Form.Control
                            type={showPassword ? "text" : "password"}
                            placeholder="Re-enter password"
                            value={formValues.confirmPassword}
                            onChange={handleChange('confirmPassword')}
                            required={isRegister}
                            className="vt-input"
                          />
                        </InputGroup>
                        {formValues.confirmPassword && formValues.password !== formValues.confirmPassword && (
                          <small className="text-danger">Passwords do not match</small>
                        )}
                      </Form.Group>
                    )}

                    {isRegister && !requiresOtp && recaptchaSiteKey && (
                      <Form.Group className="mb-3" controlId="authCaptchaRegister">
                        <Form.Label>Security Verification</Form.Label>
                        <div className="mb-2">
                          {formValues.captchaToken ? (
                            <Alert variant="success" className="py-2 px-3 mb-2">
                              <small>✓ CAPTCHA verified. You can proceed with registration.</small>
                            </Alert>
                          ) : !captchaReady ? (
                            <Alert variant="info" className="py-2 px-3 mb-2">
                              <small>Loading CAPTCHA... Please wait a moment.</small>
                            </Alert>
                          ) : null}
                        </div>
                        <div 
                          ref={captchaRefRegister}
                          className="d-flex justify-content-center"
                          style={{ minHeight: '78px' }}
                        />
                        <Form.Text className="text-muted">
                          Please verify that you are not a robot to continue with registration.
                        </Form.Text>
                      </Form.Group>
                    )}

                    {isRegister && requiresOtp && (
                      <Form.Group className="mb-3" controlId="authOtp">
                        <Form.Label>Email OTP</Form.Label>
                        <InputGroup>
                          <InputGroup.Text>
                            <ShieldLock size={18} />
                          </InputGroup.Text>
                          <Form.Control
                            type="text"
                            placeholder="Enter 6-digit OTP"
                            value={formValues.otp}
                            onChange={handleChange('otp')}
                            required
                            className="vt-input"
                            maxLength={6}
                          />
                        </InputGroup>
                        <Form.Text className="text-muted">
                          {otpExpiresIn
                            ? `OTP is valid for ${Math.round(otpExpiresIn / 60)} minutes.`
                            : 'Check your inbox for the OTP code.'}
                        </Form.Text>
                      </Form.Group>
                    )}

                    {requires2FA && (
                      <Form.Group className="mb-3" controlId="auth2FA">
                        <Form.Label>2FA Code</Form.Label>
                        <InputGroup>
                          <InputGroup.Text>
                            <ShieldLock size={18} />
                          </InputGroup.Text>
                          <Form.Control
                            type="text"
                            placeholder="Enter 6-digit code from Google Authenticator"
                            value={formValues.twoFactorToken}
                            onChange={handleChange('twoFactorToken')}
                            required
                            className="vt-input"
                            maxLength={6}
                          />
                        </InputGroup>
                        <Form.Text className="text-muted">
                          Open Google Authenticator and enter the current 6-digit code
                        </Form.Text>
                      </Form.Group>
                    )}

                    {requiresCaptcha && (
                      <Form.Group className="mb-3" controlId="authCaptcha">
                        <Form.Label>CAPTCHA Verification</Form.Label>
                        <div className="mb-2">
                          {formValues.captchaToken ? (
                            <Alert variant="success" className="py-2 px-3 mb-2">
                              <small>✓ CAPTCHA verified. Click Login to continue.</small>
                            </Alert>
                          ) : !captchaReady ? (
                            <Alert variant="info" className="py-2 px-3 mb-2">
                              <small>Loading CAPTCHA... Please wait a moment.</small>
                            </Alert>
                          ) : null}
                        </div>
                        <div 
                          ref={captchaRef}
                          className="d-flex justify-content-center"
                          style={{ minHeight: '78px' }}
                        />
                        <Form.Text className="text-muted">
                          Password is correct. Please tick "I'm not a robot" to finish CAPTCHA verification.
                        </Form.Text>
                      </Form.Group>
                    )}

                    {/* End of login/register / reset conditional blocks */}
                  </>
                )}

                    {error && (
                      <Alert variant="danger" className="py-2 px-3 mb-3">
                        <small>{error}</small>
                      </Alert>
                    )}

                    {success && (
                      <Alert variant="success" className="py-2 px-3 mb-3">
                        <small>{success}</small>
                      </Alert>
                    )}

                    <Button
                      type="submit"
                      variant="primary"
                      size="lg"
                      className="w-100 auth-submit mt-2"
                      disabled={!isValid || loading}
                    >
                      {loading
                        ? 'Processing...'
                        : isResettingPassword
                          ? requiresResetOtp
                            ? 'Verify OTP & Reset'
                            : 'Send Reset OTP'
                          : isRegister
                            ? requiresOtp
                              ? 'Verify OTP & Register'
                              : 'Register & Access'
                            : requires2FA
                              ? 'Verify 2FA'
                              : 'Login'}
                      <ArrowRight size={18} className="ms-2" />
                    </Button>
                  </Form>

                  <div className="auth-card__footer d-flex flex-column align-items-start gap-2">
                    {isResettingPassword ? (
                      <>
                        <div className="w-100 text-start">
                          Remembered your password?
                          <button type="button" className="auth-switch ms-2" onClick={() => setIsResettingPassword(false)}>
                            Back to Login
                          </button>
                        </div>
                      </>
                    ) : (
                      <>
                        <div className="w-100 text-start">
                          {isRegister ? 'Already have an account?' : "Don't have an account?"}
                          <button type="button" className="auth-switch ms-2" onClick={toggleMode}>
                            {isRegister ? 'Login' : 'Create Account Now'}
                          </button>
                        </div>
                        {!isRegister && (
                          <div className="w-100 text-start">
                            Forgot password?
                            <button
                              type="button"
                              className="auth-switch ms-2"
                              onClick={() => {
                                setError('');
                                setSuccess('');
                                setIsResettingPassword(true);
                                setRequiresResetOtp(false);
                                setFormValues(defaultForm);
                              }}
                            >
                              Reset it here
                            </button>
                          </div>
                        )}
                      </>
                    )}
                  </div>
                </Card.Body>
              </Card>
            </Col>
          </Row>
        </Container>
      </div>

      {/* Email Verification Modal */}
      <Modal show={showVerificationModal} onHide={() => setShowVerificationModal(false)} centered>
        <Modal.Header closeButton>
                  <Modal.Title>Email Verification</Modal.Title>
                </Modal.Header>
                <Modal.Body>
                  <p>
                    We've sent a verification email to <strong>{verificationEmail}</strong>.
                    Please check your inbox and click the verification link to activate your account.
                  </p>
                  <p className="text-muted small">
                    If you don't see the email, please check your spam folder.
                  </p>
                </Modal.Body>
                <Modal.Footer>
                  <Button variant="secondary" onClick={() => setShowVerificationModal(false)}>
                    Close
                  </Button>
                  <Button variant="primary" onClick={handleResendVerification} disabled={loading}>
                    {loading ? 'Sending...' : 'Resend email'}
                  </Button>
                </Modal.Footer>
      </Modal>
    </>
  );
};

export default AuthPage;
