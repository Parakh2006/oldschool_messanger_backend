require("dotenv").config();
const JWT_SECRET = process.env.JWT_SECRET;
const express = require("express");
const cors = require("cors");
const http = require("http");
const { Server } = require("socket.io");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const connectDB = require("./db");
const User = require("./models/users");
const Conversation = require("./models/Conversation");
const authMiddleware = require("./authMiddleware");
const Message = require("./models/Message");

const Otp = require("./models/Otp");



const PHONE_REGEX = /^[0-9]{8,15}$/;

connectDB();

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: process.env.CORS_ORIGIN,
    methods: ["GET", "POST"],
    credentials: true,
  },
});


app.use(
  cors({
    origin: process.env.CORS_ORIGIN || "http://localhost:3000",
    credentials: true,
  })
);

const helmet = require("helmet");
app.use(helmet());

app.use(express.json());

// In-memory store only for status/read receipts
const messageStore = {};
const onlineUsers = new Map();

app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

app.get("/echo", (req, res) => {
  res.json({ message: "This is GET /echo working" });
});

app.post("/echo", (req, res) => {
  res.json(req.body);
});

app.post("/signup", async (req, res) => {
  const { username, password, phoneNumber } = req.body;

  if (!username || !password || !phoneNumber) {
    return res
      .status(400)
      .json({ message: "Username, phone number and password are required" });
  }

  if (!PHONE_REGEX.test(phoneNumber)) {
    return res.status(400).json({ message: "Invalid phone number" });
  }

  try {
    const existingUser = await User.findOne({
      $or: [{ username }, { phoneNumber }],
    });

    if (existingUser) {
      if (existingUser.username === username) {
        return res.status(400).json({ message: "Username already taken" });
      }
      if (existingUser.phoneNumber === phoneNumber) {
        return res
          .status(400)
          .json({ message: "Phone number already in use" });
      }
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
  } catch (error) {
    console.error("Signup error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res
      .status(400)
      .json({ message: "Username and password are required" });
  }

  try {
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(401).json({ message: "Invalid username or password" });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ message: "Invalid username or password" });
    }

    const token = jwt.sign(
      {
        userId: user._id.toString(),
        username: user.username,
      },
      JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({
      message: "Login successful",
      userId: user._id,
      username: user.username,
      token,
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});
/**
 * 🔐 POST /auth/request-otp
 * Body: { phoneNumber }
 * Dev mode: logs the OTP to console instead of sending SMS
 */
app.post("/auth/request-otp", async (req, res) => {
  try {
    const { phoneNumber } = req.body;

    if (!phoneNumber) {
      return res.status(400).json({ message: "phoneNumber is required" });
    }

    if (!PHONE_REGEX.test(phoneNumber)) {
      return res.status(400).json({ message: "Invalid phone number" });
    }

    // For now: OTP login only for existing users
    const user = await User.findOne({ phoneNumber });
    if (!user) {
      return res
        .status(404)
        .json({ message: "No user found with this phone number" });
    }

    // 6-digit code
    const code = Math.floor(100000 + Math.random() * 900000).toString();

    // Hash OTP before saving
    const codeHash = await bcrypt.hash(code, 10);

    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    await Otp.create({
      phoneNumber,
      codeHash,
      expiresAt,
      used: false,
    });

    // Dev mode: log OTP instead of sending SMS
    console.log(`📱 OTP for ${phoneNumber}: ${code}`);

    return res.json({
      message: "OTP generated (dev mode)",
      expiresAt,
    });
  } catch (err) {
    console.error("Request OTP error:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
});
/**
 * 🔐 POST /auth/verify-otp
 * Body: { phoneNumber, code }
 * Checks latest OTP, verifies, issues JWT (same as /login)
 */
app.post("/auth/verify-otp", async (req, res) => {
  try {
    const { phoneNumber, code } = req.body;

    if (!phoneNumber || !code) {
      return res
        .status(400)
        .json({ message: "phoneNumber and code are required" });
    }

    if (!PHONE_REGEX.test(phoneNumber)) {
      return res.status(400).json({ message: "Invalid phone number" });
    }

    // Get latest OTP for this phone
    const otpEntry = await Otp.findOne({ phoneNumber })
      .sort({ createdAt: -1 })
      .exec();

    if (!otpEntry) {
      return res.status(400).json({ message: "No OTP found for this number" });
    }

    if (otpEntry.used) {
      return res.status(400).json({ message: "OTP already used" });
    }

    if (otpEntry.expiresAt < new Date()) {
      return res.status(400).json({ message: "OTP has expired" });
    }

    const isMatch = await bcrypt.compare(code, otpEntry.codeHash);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid OTP code" });
    }

    // Mark OTP as used
    otpEntry.used = true;
    await otpEntry.save();

    // Find user for this phone
    const user = await User.findOne({ phoneNumber });
    if (!user) {
      // In future: auto-create user here if you want OTP-only signup
      return res
        .status(404)
        .json({ message: "User not found for this phone number" });
    }

    // Issue JWT (same payload as /login)
    const token = jwt.sign(
      {
        userId: user._id.toString(),
        username: user.username,
      },
      JWT_SECRET,
      { expiresIn: "1d" }
    );

    return res.json({
      message: "OTP verified",
      userId: user._id,
      username: user.username,
      token,
    });
  } catch (err) {
    console.error("Verify OTP error:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
});


app.post("/conversations", authMiddleware, async (req, res) => {
  try {
    const { userId1, userId2 } = req.body;

    if (!userId1 || !userId2) {
      return res
        .status(400)
        .json({ message: "userId1 and userId2 are required" });
    }

    if (userId1 === userId2) {
      return res.status(400).json({ message: "You cannot chat with yourself" });
    }

    const existing = await Conversation.findOne({
      participants: { $all: [userId1, userId2] },
      isGroup: false,
    });

    if (existing) {
      return res.status(200).json({
        message: "Conversation already exists",
        conversationId: existing._id,
      });
    }

    const newConversation = await Conversation.create({
      participants: [userId1, userId2],
      isGroup: false,
    });

    return res.status(201).json({
      message: "Conversation created",
      conversationId: newConversation._id,
    });
  } catch (error) {
    console.error("Create conversation error:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/conversations/by-phone", authMiddleware, async (req, res) => {
  const { myUserId, otherPhone } = req.body;

  if (!myUserId || !otherPhone) {
    return res
      .status(400)
      .json({ message: "myUserId and otherPhone are required" });
  }

  try {
    const otherUser = await User.findOne({ phoneNumber: otherPhone });

    if (!otherUser) {
      return res
        .status(404)
        .json({ message: "No user found with that phone number" });
    }

    if (otherUser._id.toString() === myUserId.toString()) {
      return res.status(400).json({ message: "You cannot chat with yourself" });
    }

    let existing = await Conversation.findOne({
      participants: { $all: [myUserId, otherUser._id] },
      isGroup: false,
    });

    if (existing) {
      return res.json({
        message: "Conversation already exists",
        conversationId: existing._id,
        otherUserId: otherUser._id,
        otherUsername: otherUser.username,
      });
    }

    const newConv = await Conversation.create({
      participants: [myUserId, otherUser._id],
      isGroup: false,
    });

    return res.status(201).json({
      message: "Conversation created",
      conversationId: newConv._id,
      otherUserId: otherUser._id,
      otherUsername: otherUser.username,
    });
  } catch (error) {
    console.error("Start chat by phone error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/conversations/:userId", authMiddleware, async (req, res) => {
  try {
    const userId = req.params.userId;

    const conversations = await Conversation.find({
      participants: userId,
    });

    const enriched = [];

    for (const c of conversations) {
      const otherUserId = c.participants.find(
        (p) => p.toString() !== userId.toString()
      );

      const otherUser = await User.findById(otherUserId);

      enriched.push({
        _id: c._id,
        otherUserId,
        otherUsername: otherUser ? otherUser.username : "Unknown",
      });
    }

    res.json({ conversations: enriched });
  } catch (error) {
    console.error("Get conversations error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

/**
 * 🔐 POST /messages
 * Body: { conversationId, ciphertext, iv }
 */
app.post("/messages", authMiddleware, async (req, res) => {
  try {
    const { conversationId, ciphertext, iv } = req.body;

    if (!conversationId || !ciphertext || !iv) {
      return res.status(400).json({
        message: "conversationId, ciphertext and iv are required",
      });
    }

    if (ciphertext.length > 5000) {
      return res.status(400).json({ message: "Message too long" });
    }

    const conversation = await Conversation.findById(conversationId);
    if (!conversation) {
      return res.status(400).json({ message: "Conversation does not exist" });
    }

    const senderId = req.userId || (req.user && req.user.userId);
    if (!senderId) {
      return res.status(401).json({ message: "Invalid auth (no senderId)" });
    }

    const isParticipant = conversation.participants.some(
      (p) => p.toString() === senderId.toString()
    );

    if (!isParticipant) {
      return res
        .status(400)
        .json({ message: "Sender is not part of this conversation" });
    }

    const messageDoc = await Message.create({
      conversationId,
      senderId,
      ciphertext,
      iv,
    });

    const participants = conversation.participants.map((p) => p.toString());
    const recipientId = participants.find((p) => p !== senderId.toString());
    let status = "sent";

    if (recipientId && onlineUsers.has(recipientId)) {
      status = "delivered";
    }

    const newMessage = {
      _id: messageDoc._id.toString(),
      conversationId: conversationId.toString(),
      senderId: senderId.toString(),
      ciphertext,
      iv,
      createdAt: messageDoc.createdAt.toISOString(),
      status,
    };

    if (!messageStore[conversationId]) {
      messageStore[conversationId] = [];
    }
    messageStore[conversationId].push(newMessage);

    io.to(conversationId.toString()).emit("newMessage", newMessage);

    res.status(201).json({
      message: "Message sent",
      data: newMessage,
    });
  } catch (error) {
    console.error("Send message error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

/**
 * 🔐 GET /messages?conversationId=...
 * Returns encrypted messages from MongoDB
 */
app.get("/messages", authMiddleware, async (req, res) => {
  try {
    const { conversationId } = req.query;

    if (!conversationId) {
      return res.status(400).json({
        message: "conversationId is required",
      });
    }

    const conversation = await Conversation.findById(conversationId);
    if (!conversation) {
      return res.status(400).json({ message: "Conversation does not exist" });
    }

    const messages = await Message.find({ conversationId })
      .sort({ createdAt: 1 })
      .exec();

    res.json({ messages });
  } catch (error) {
    console.error("Get messages error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/users/:userId/presence", authMiddleware, async (req, res) => {
  try {
    const userId = req.params.userId;

    const user = await User.findById(userId).select("username lastSeen");
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const online = onlineUsers.has(userId.toString());

    res.json({
      userId: user._id.toString(),
      username: user.username,
      online,
      lastSeen: user.lastSeen,
    });
  } catch (error) {
    console.error("Presence fetch error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

io.on("connection", (socket) => {
  console.log("Socket connected:", socket.id);

  socket.on("registerUser", async (userId) => {
    if (!userId) return;

    userId = userId.toString();
    socket.data.userId = userId;

    if (!onlineUsers.has(userId)) {
      onlineUsers.set(userId, new Set());
    }
    onlineUsers.get(userId).add(socket.id);

    io.emit("presenceUpdate", {
      userId,
      online: true,
      lastSeen: null,
    });
  });

  socket.on("joinConversation", (conversationId) => {
    if (!conversationId) return;
    socket.join(conversationId.toString());
  });

  socket.on("conversationRead", ({ conversationId, userId }) => {
    if (!conversationId || !userId) return;
    conversationId = conversationId.toString();
    userId = userId.toString();

    const msgs = messageStore[conversationId];
    if (!msgs) return;

    const updates = [];

    msgs.forEach((m) => {
      if (m.senderId && m.senderId !== userId && m.status !== "read") {
        m.status = "read";
        updates.push({
          messageId: m._id,
          status: m.status,
          conversationId,
        });
      }
    });

    updates.forEach((u) => {
      io.to(conversationId).emit("messageStatusUpdate", u);
    });
  });

  socket.on("typing", ({ conversationId, userId }) => {
    if (!conversationId || !userId) return;
    conversationId = conversationId.toString();
    socket.to(conversationId).emit("typing", {
      conversationId,
      userId: userId.toString(),
    });
  });

  socket.on("stopTyping", ({ conversationId, userId }) => {
    if (!conversationId || !userId) return;
    conversationId = conversationId.toString();
    socket.to(conversationId).emit("stopTyping", {
      conversationId,
      userId: userId.toString(),
    });
  });

  socket.on("disconnect", async () => {
    const userId = socket.data.userId;

    if (userId && onlineUsers.has(userId)) {
      const set = onlineUsers.get(userId);
      set.delete(socket.id);
      if (set.size === 0) {
        onlineUsers.delete(userId);

        const now = new Date();
        try {
          await User.findByIdAndUpdate(userId, { lastSeen: now });
        } catch (err) {
          console.error("Error updating lastSeen:", err);
        }

        io.emit("presenceUpdate", {
          userId,
          online: false,
          lastSeen: now.toISOString(),
        });
      }
    }
  });
});
const PORT = process.env.PORT || 4000;

server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});


