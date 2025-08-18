const crypto = require('crypto');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');

/**
 * Generate TOTP Secret for a user
 */
function generateTOTPSecret(email) {
  return speakeasy.generateSecret({ name: `ForumWeb (${email})` });
}

/**
 * Verify TOTP code
 */
function verifyTOTP(secret, token) {
  return speakeasy.totp.verify({
    secret,
    encoding: 'base32',
    token,
    window: 2 // allow small clock drift
  });
}

/**
 * Generate simple device fingerprint (userAgent+screen+random)
 */
function generateDeviceFingerprint({ userAgent, screen, salt }) {
  const raw = `${userAgent}|${screen}|${salt}`;
  return crypto.createHash('sha256').update(raw).digest('hex');
}
                                                                                 /**
 * Generate RSA keypair for device
 */
function generateKeypair() {
  return crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
}

/**
 * Generate QR code for TOTP secret                                               */
async function generateQRCode(otpauth_url) {                                       return await qrcode.toDataURL(otpauth_url);
}
                                                                                 module.exports = {
  generateTOTPSecret,
  verifyTOTP,
  generateDeviceFingerprint,
  generateKeypair,
  generateQRCode
};
