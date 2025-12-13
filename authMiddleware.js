const jwt = require("jsonwebtoken");

const JWT_SECRET = "galiyoon-ultra-secret-key";

const authMiddleware = (req, res, next) => {
  try {
    const authHeader = req.header("Authorization");

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Authentication required" });
    }

    const token = authHeader.split(" ")[1];

    const decoded = jwt.verify(token, JWT_SECRET);

    // Attach user info in both formats
    req.user = {
      userId: decoded.userId,
      username: decoded.username,
    };

    req.userId = decoded.userId;
    req.username = decoded.username;

    next();
  } catch (error) {
    console.error("Auth error:", error);
    return res.status(401).json({ message: "Invalid or expired token" });
  }
};

module.exports = authMiddleware;
