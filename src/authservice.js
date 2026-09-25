import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-key';
const failedLoginAttempts = new Map();

/**
 * User Authentication with MFA & IP Rate Limiting
 */
export async function loginUser(username, password, db, mfaCode, clientIp) {
  // 1. IP-based rate limiting check
  const attempts = failedLoginAttempts.get(clientIp) || 0;
  if (attempts >= 5) {
    throw new Error('Too many login attempts. Account temporarily locked.');
  }

  const user = await db.findUserByUsername(username);
  if (!user) {
    failedLoginAttempts.set(clientIp, attempts + 1);
    throw new Error('Invalid credentials');
  }

  const isValidPassword = await bcrypt.compare(password, user.passwordHash);
  if (!isValidPassword) {
    failedLoginAttempts.set(clientIp, attempts + 1);
    throw new Error('Invalid credentials');
  }

  // 2. Multi-Factor Authentication (MFA) Verification
  if (user.mfaEnabled) {
    if (!mfaCode) {
      return { mfaRequired: true, message: 'Please provide 6-digit TOTP code' };
    }
    const isMfaValid = await db.verifyTotp(user.id, mfaCode);
    if (!isMfaValid) {
      throw new Error('Invalid MFA authentication code');
    }
  }

  // Reset rate limiting counter on success
  failedLoginAttempts.delete(clientIp);

  const token = jwt.sign(
    { userId: user.id, username: user.username, mfaVerified: true },
    JWT_SECRET,
    { expiresIn: '2h' }
  );

  return {
    success: true,
    token,
    user: { id: user.id, username: user.username }
  };
}