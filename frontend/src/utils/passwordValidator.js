/**
 * Password validation utility
 * Validates password strength according to security requirements
 */

export const validatePassword = (password) => {
  const errors = [];
  const checks = {
    minLength: password.length >= 8,
    hasUpperCase: /[A-Z]/.test(password),
    hasLowerCase: /[a-z]/.test(password),
    hasNumber: /[0-9]/.test(password),
    hasSpecialChar: /[!@#$%^&*(),.?":{}|<>_+\-=\[\]\\';\/]/.test(password),
    notCommon: !['password', '12345678', 'qwerty123', 'admin123', 'welcome123'].includes(password.toLowerCase()),
  };

  if (!checks.minLength) {
    errors.push('Password must be at least 8 characters');
  }
  if (!checks.hasUpperCase) {
    errors.push('At least one uppercase letter required');
  }
  if (!checks.hasLowerCase) {
    errors.push('At least one lowercase letter required');
  }
  if (!checks.hasNumber) {
    errors.push('At least one number required');
  }
  if (!checks.hasSpecialChar) {
    errors.push('At least one special character required (!@#$%^&*...)');
  }
  if (!checks.notCommon) {
    errors.push('Password is too common, please choose another');
  }

  const strength = Object.values(checks).filter(Boolean).length;
  let strengthLevel = 'weak';
  if (strength >= 5) strengthLevel = 'strong';
  else if (strength >= 3) strengthLevel = 'medium';

  return {
    isValid: errors.length === 0,
    errors,
    strength: strengthLevel,
    score: strength,
  };
};



























