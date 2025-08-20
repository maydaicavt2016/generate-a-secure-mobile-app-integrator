const crypto = require('crypto');

class SecureMobileAppIntegrator {
  constructor(appId, appSecret) {
    this.appId = appId;
    this.appSecret = appSecret;
  }

  generateToken(userId) {
    const tokenData = {
      userId,
      appId: this.appId,
      timestamp: Date.now(),
    };

    const token = crypto.createHmac('sha256', this.appSecret)
      .update(JSON.stringify(tokenData))
      .digest('base64');

    return token;
  }

  verifyToken(token) {
    const decodedToken = crypto.createHmac('sha256', this.appSecret)
      .update(token)
      .digest('base64');

    const tokenData = JSON.parse(decodedToken);

    if (tokenData.appId !== this.appId) {
      throw new Error('Invalid app ID');
    }

    if (tokenData.timestamp < Date.now() - 300000) {
      throw new Error('Token has expired');
    }

    return tokenData.userId;
  }
}

// Test case
const integrator = new SecureMobileAppIntegrator('myAppId', 'myAppSecret');

const userId = 'user123';
const token = integrator.generateToken(userId);
console.log(`Generated token: ${token}`);

try {
  const verifiedUserId = integrator.verifyToken(token);
  console.log(`Verified user ID: ${verifiedUserId}`);
} catch (error) {
  console.error(`Error verifying token: ${error.message}`);
}