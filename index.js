require("dotenv").config();

const express = require("express");
const cors = require("cors");
const http = require("http");
const { Server } = require("socket.io");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");

const connectDB = require("./db");
const User = require("./models/users");
const Conversation = require("./models/Conversation");
const Message = require("./models/Message");
const Otp = require("./models/Otp");
const authMiddleware = require("./authMiddleware");

const JWT_SECRET = process.env.JWT_SECRET;
const PHONE_REGEX = /^[0-9]{8,15}$/;

// -------------------- CONNECT DB --------------------
connectDB();

// -------------------- APP SETUP --------------------
const app = express();
const server = http.createServer(app);

// ✅ ALLOWED ORIGINS (FIXES YOUR CORS ISSUE)
const allowedOrigins = [
  "http://localhost:3000",
  "https://oldschool-messanger-frontend.vercel.app",
];

// -------------------- MIDDLEWARE --------------------
app.use(
  cors({
    origin: allowedOrigins,
    credentials: true,
  })
);

app.use(helmet());
app.use(express.json());

// -------------------- SOCKET.IO --------------------
const io = new Server(server, {
  cors: {
    origin: allowedOrigins,
    methods: ["GET", "POST"],
    credentials: true,
  },
});

// -------------------- IN-MEMORY STATE --------------------
const messageStore = {};
const onlineUsers = new Map();

// -------------------- BASIC ROUTES --------------------
app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

app.get("/echo", (req, res) => {
  res.json({ message: "This is GET /echo working" });
});

app.post("/echo", (req, res) => {
  res.json(req.body);
});

// -------------------- AUTH --------------------
app.post("/signup", async (req, res) => {
  const { username, password, phoneNumber } = req.body;

  if (!username || !password || !phoneNumber) {
    return res.status(400).json({ message: "All fields required" });
  }

  if (!PHONE_REGEX.test(phoneNumber)) {
    return res.status(400).json({ message: "Invalid phone number" });
  }

  try {
    const existingUser = await User.findOne({
      $or: [{ username }, { phoneNumber }],
    });

    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await User.create({
      username,
      phoneNumber,
      password: hashedPassword,
    });

    res.status(201).json({
      message: "Signup successful",
      userId: newUser._id,
      username: newUser.username,
    });
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ message: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: "Invalid credentials" });

    const token = jwt.sign(
      { userId: user._id.toString(), username: user.username },
      JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({
      message: "Login successful",
      token,
      userId: user._id,
      username: user.username,
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

// -------------------- OTP --------------------
app.post("/auth/request-otp", async (req, res) => {
  const { phoneNumber } = req.body;

  if (!PHONE_REGEX.test(phoneNumber)) {
    return res.status(400).json({ message: "Invalid phone number" });
  }

  const user = await User.findOne({ phoneNumber });
  if (!user) return res.status(404).json({ message: "User not found" });

  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const codeHash = await bcrypt.hash(code, 10);

  await Otp.create({
    phoneNumber,
    codeHash,
    expiresAt: new Date(Date.now() + 10 * 60 * 1000),
    used: false,
  });

  console.log(`📱 OTP for ${phoneNumber}: ${code}`);
  res.json({ message: "OTP generated (dev mode)" });
});

app.post("/auth/verify-otp", async (req, res) => {
  const { phoneNumber, code } = req.body;

  const otp = await Otp.findOne({ phoneNumber }).sort({ createdAt: -1 });
  if (!otp || otp.used || otp.expiresAt < new Date()) {
    return res.status(400).json({ message: "Invalid OTP" });
  }

  const valid = await bcrypt.compare(code, otp.codeHash);
  if (!valid) return res.status(400).json({ message: "Invalid OTP" });

  otp.used = true;
  await otp.save();

  const user = await User.findOne({ phoneNumber });

  const token = jwt.sign(
    { userId: user._id.toString(), username: user.username },
    JWT_SECRET,
    { expiresIn: "1d" }
  );

  res.json({
    message: "OTP verified",
    token,
    userId: user._id,
    username: user.username,
  });
});

// -------------------- SOCKET EVENTS --------------------
io.on("connection", (socket) => {
  socket.on("registerUser", (userId) => {
    if (!onlineUsers.has(userId)) onlineUsers.set(userId, new Set());
    onlineUsers.get(userId).add(socket.id);
  });

  socket.on("joinConversation", (conversationId) => {
    socket.join(conversationId);
  });

  socket.on("disconnect", () => {
    for (const [userId, sockets] of onlineUsers.entries()) {
      sockets.delete(socket.id);
      if (sockets.size === 0) onlineUsers.delete(userId);
    }
  });
});

// -------------------- START SERVER --------------------
const PORT = process.env.PORT || 4000;

server.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
