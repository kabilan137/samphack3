import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-key';

/**
 * User Authentication with Role-Based Access Control (RBAC) & Audit Logging
 */
export async function loginUser(username, password, db, auditLogger) {
  const user = await db.findUserByUsername(username);
  if (!user) {
    if (auditLogger) auditLogger.warn(`Failed login: user ${username} not found`);
    throw new Error('User not found');
  }

  const isValidPassword = await bcrypt.compare(password, user.passwordHash);
  if (!isValidPassword) {
    if (auditLogger) auditLogger.warn(`Failed login: wrong password for ${username}`);
    throw new Error('Invalid credentials');
  }

  // Role extraction and permissions lookup
  const userRoles = await db.getUserRoles(user.id);
  const permissions = await db.getPermissionsForRoles(userRoles);

  const token = jwt.sign(
    {
      userId: user.id,
      username: user.username,
      roles: userRoles,
      permissions: permissions
    },
    JWT_SECRET,
    { expiresIn: '30m' }
  );

  if (auditLogger) {
    auditLogger.info(`Successful login: user ${username} with roles [${userRoles.join(', ')}]`);
  }

  return {
    success: true,
    token,
    user: { id: user.id, username: user.username, roles: userRoles }
  };
}
