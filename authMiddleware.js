const jwt = require("jsonwebtoken");

function getTokenFromHeader(req) {
  const auth = req.headers.authorization;
  if (!auth) return null;

  const parts = auth.trim().split(/\s+/);
  if (parts.length < 2) return null;

  const scheme = parts[0];
  const token = parts.slice(1).join(" ");

  if (!/^Bearer$/i.test(scheme)) return null;

  return token.trim();
}

module.exports = function authMiddleware(req, res, next) {
  const token = getTokenFromHeader(req);

  if (!token) {
    return res.status(401).json({
      ok: false,
      code: "AUTH_MISSING_TOKEN",
      message: "Please log in again.",
    });
  }

  const secret = (process.env.JWT_SECRET || "").trim();

  if (!secret || secret.length < 20) {
    return res.status(500).json({
      ok: false,
      code: "AUTH_SERVER_MISCONFIG",
      message: "Server auth misconfigured. Please try again later.",
    });
  }

  try {
    const decoded = jwt.verify(token, secret);

    // ✅ Consistent fields for your routes
    req.user = decoded;
    req.userId = decoded.userId;
    req.username = decoded.username;

    return next();
  } catch (err) {
    if (err.name === "TokenExpiredError") {
      return res.status(401).json({
        ok: false,
        code: "AUTH_TOKEN_EXPIRED",
        message: "Session expired. Please log in again.",
      });
    }

    return res.status(401).json({
      ok: false,
      code: "AUTH_TOKEN_INVALID",
      message: "Session invalid. Please log in again.",
    });
  }
};
