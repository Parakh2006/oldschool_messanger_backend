// authMiddleware.js
const jwt = require("jsonwebtoken");

/**
 * Robust JWT auth middleware for Express
 * - Accepts: Authorization: Bearer <token>
 * - Adds: req.user = decoded payload
 * - Returns user-friendly errors (no stack traces / no secret leakage)
 */

function getTokenFromHeader(req) {
  const auth = req.headers.authorization;

  if (!auth) return null;

  // Handle accidental cases like:
  // "Bearer Bearer <token>" or extra spaces
  const parts = auth.trim().split(/\s+/); // split by any whitespace

  if (parts.length < 2) return null;

  const scheme = parts[0];
  const token = parts.slice(1).join(" "); // in case something weird got split

  if (!/^Bearer$/i.test(scheme)) return null;

  return token.trim();
}

module.exports = function authMiddleware(req, res, next) {
  const token = getTokenFromHeader(req);

  // 1) Missing token
  if (!token) {
    return res.status(401).json({
      ok: false,
      code: "AUTH_MISSING_TOKEN",
      message: "You are not logged in. Please log in again.",
    });
  }

  // 2) Missing secret (VERY common on Render when env var not set)
  const secret = process.env.JWT_SECRET;

  if (!secret || typeof secret !== "string" || secret.trim().length < 10) {
    // Don’t expose the secret. But DO expose that it’s missing/misconfigured.
    return res.status(500).json({
      ok: false,
      code: "AUTH_SERVER_MISCONFIG",
      message:
        "Server auth is misconfigured (JWT secret missing). Please contact support.",
    });
  }

  try {
    // NOTE: If you use a specific algorithm when signing, keep it consistent here.
    // If you sign with default HS256, this is fine.
    const decoded = jwt.verify(token, secret.trim());

    // Attach decoded payload for later handlers
    req.user = decoded;

    return next();
  } catch (err) {
    // Make errors user-friendly & actionable
    if (err.name === "TokenExpiredError") {
      return res.status(401).json({
        ok: false,
        code: "AUTH_TOKEN_EXPIRED",
        message: "Session expired. Please log in again.",
      });
    }

    if (err.name === "JsonWebTokenError") {
      // invalid signature / malformed / etc.
      return res.status(401).json({
        ok: false,
        code: "AUTH_TOKEN_INVALID",
        message:
          "Your session is invalid (token mismatch). Please log in again.",
        // Helpful debug hints without leaking secrets/tokens:
        hints: [
          "This usually happens if the server JWT_SECRET changed after you logged in.",
          "Or the frontend is sending an old token from localStorage.",
        ],
      });
    }

    return res.status(401).json({
      ok: false,
      code: "AUTH_FAILED",
      message: "Authentication failed. Please log in again.",
    });
  }
};
