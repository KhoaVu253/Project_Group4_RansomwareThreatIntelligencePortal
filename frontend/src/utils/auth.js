import CryptoJS from 'crypto-js';

/**
 * Security utilities for authentication
 */

// Secret key for additional encryption (should be in .env in production)
const ENCRYPTION_KEY = 'your-secret-key-change-in-production';

/**
 * Hash password using SHA-256 with email salt
 */
export const hashPassword = (password, email) => {
  const salt = email.toLowerCase().trim();
  return CryptoJS.SHA256(password + salt).toString();
};

/**
 * Encrypt sensitive data before storing in localStorage
 */
export const encryptData = (data) => {
  try {
    return CryptoJS.AES.encrypt(JSON.stringify(data), ENCRYPTION_KEY).toString();
  } catch (error) {
    console.error('Encryption failed:', error);
    return null;
  }
};

/**
 * Decrypt data from localStorage
 */
export const decryptData = (encryptedData) => {
  try {
    const bytes = CryptoJS.AES.decrypt(encryptedData, ENCRYPTION_KEY);
    const decryptedString = bytes.toString(CryptoJS.enc.Utf8);
    return JSON.parse(decryptedString);
  } catch (error) {
    console.error('Decryption failed:', error);
    return null;
  }
};

/**
 * Validate email format
 */
export const validateEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

/**
 * Validate password strength
 * Returns: { isValid: boolean, message: string }
 */
export const validatePassword = (password) => {
  if (password.length < 8) {
    return { isValid: false, message: 'Password must be at least 8 characters long' };
  }
  
  if (!/[A-Z]/.test(password)) {
    return { isValid: false, message: 'Password must contain at least 1 uppercase letter' };
  }
  
  if (!/[a-z]/.test(password)) {
    return { isValid: false, message: 'Password must contain at least 1 lowercase letter' };
  }
  
  if (!/[0-9]/.test(password)) {
    return { isValid: false, message: 'Password must contain at least 1 number' };
  }
  
  if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    return { isValid: false, message: 'Password must contain at least 1 special character' };
  }
  
  return { isValid: true, message: 'Strong password' };
};

/**
 * Sanitize user input to prevent XSS
 */
export const sanitizeInput = (input) => {
  if (typeof input !== 'string') return input;
  
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
};

/**
 * Generate secure random token
 */
export const generateToken = () => {
  return CryptoJS.lib.WordArray.random(32).toString();
};

/**
 * Check if session is expired (optional - for future implementation)
 */
export const isSessionExpired = (loginTime, expiryHours = 24) => {
  if (!loginTime) return true;
  const now = new Date().getTime();
  const expiry = new Date(loginTime).getTime() + (expiryHours * 60 * 60 * 1000);
  return now > expiry;
};

/**
 * Secure localStorage wrapper with encryption
 */
export const secureStorage = {
  setItem: (key, value) => {
    const encrypted = encryptData(value);
    if (encrypted) {
      localStorage.setItem(key, encrypted);
      return true;
    }
    return false;
  },
  
  getItem: (key) => {
    const encrypted = localStorage.getItem(key);
    if (!encrypted) return null;
    return decryptData(encrypted);
  },
  
  removeItem: (key) => {
    localStorage.removeItem(key);
  },
  
  clear: () => {
    localStorage.clear();
  }
};

/**
 * Rate limiting for login attempts (client-side)
 */
const LOGIN_ATTEMPTS_KEY = 'login-attempts';
const MAX_ATTEMPTS = 5;
const LOCKOUT_TIME = 15 * 60 * 1000; // 15 minutes

export const checkLoginAttempts = (email) => {
  const attempts = JSON.parse(localStorage.getItem(LOGIN_ATTEMPTS_KEY) || '{}');
  const userAttempts = attempts[email] || { count: 0, lockoutUntil: null };
  
  // Check if locked out
  if (userAttempts.lockoutUntil && new Date() < new Date(userAttempts.lockoutUntil)) {
    const remainingMinutes = Math.ceil((new Date(userAttempts.lockoutUntil) - new Date()) / 60000);
    return {
      allowed: false,
      message: `Tài khoản tạm khóa. Thử lại sau ${remainingMinutes} phút.`
    };
  }
  
  // Reset if lockout expired
  if (userAttempts.lockoutUntil && new Date() >= new Date(userAttempts.lockoutUntil)) {
    userAttempts.count = 0;
    userAttempts.lockoutUntil = null;
  }
  
  return { allowed: true, count: userAttempts.count };
};

export const recordFailedLogin = (email) => {
  const attempts = JSON.parse(localStorage.getItem(LOGIN_ATTEMPTS_KEY) || '{}');
  const userAttempts = attempts[email] || { count: 0, lockoutUntil: null };
  
  userAttempts.count += 1;
  
  if (userAttempts.count >= MAX_ATTEMPTS) {
    userAttempts.lockoutUntil = new Date(Date.now() + LOCKOUT_TIME).toISOString();
  }
  
  attempts[email] = userAttempts;
  localStorage.setItem(LOGIN_ATTEMPTS_KEY, JSON.stringify(attempts));
  
  return userAttempts.count;
};

export const resetLoginAttempts = (email) => {
  const attempts = JSON.parse(localStorage.getItem(LOGIN_ATTEMPTS_KEY) || '{}');
  delete attempts[email];
  localStorage.setItem(LOGIN_ATTEMPTS_KEY, JSON.stringify(attempts));
};

/**
 * Get authentication token from localStorage
 * Returns the token string or null if not found
 */
export const getAuthToken = () => {
  return localStorage.getItem('vt-auth-token');
};

/**
 * Set authentication token in localStorage
 */
export const setAuthToken = (token) => {
  if (token) {
    localStorage.setItem('vt-auth-token', token);
  } else {
    localStorage.removeItem('vt-auth-token');
  }
};

/**
 * Remove authentication token and user data from localStorage
 */
export const clearAuthData = () => {
  localStorage.removeItem('vt-auth-token');
  localStorage.removeItem('vt-auth-user');
};