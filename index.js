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

// ✅ Always trim once and use everywhere
const JWT_SECRET = (process.env.JWT_SECRET || "").trim();

if (!JWT_SECRET || JWT_SECRET.length < 20) {
  console.error("❌ JWT_SECRET missing/too short. Fix Render env vars.");
  process.exit(1);
}

const PHONE_REGEX = /^[0-9]{8,15}$/;

// -------------------- DB --------------------
connectDB();

// -------------------- APP --------------------
const app = express();
const server = http.createServer(app);

// -------------------- CORS --------------------
const allowedOrigins = [
  "http://localhost:3000",
  "https://oldschool-messanger-frontend.vercel.app",
];

// allow function so socket.io + express both behave well
const corsOptions = {
  origin: (origin, callback) => {
    // allow non-browser requests (like Postman) where origin is undefined
    if (!origin) return callback(null, true);

    if (allowedOrigins.includes(origin)) return callback(null, true);

    return callback(new Error("Not allowed by CORS: " + origin));
  },
  credentials: true,
};

app.use(cors(corsOptions));
app.use(helmet());
app.use(express.json());

// -------------------- SOCKET --------------------
const io = new Server(server, {
  cors: {
    origin: allowedOrigins, // socket.io accepts array directly
    methods: ["GET", "POST"],
    credentials: true,
  },
});

// store io in app (useful later)
app.set("io", io);

// -------------------- HEALTH --------------------
app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

// -------------------- AUTH --------------------
app.post("/signup", async (req, res) => {
  try {
    const { username, password, phoneNumber } = req.body;

    if (!username || !password || !phoneNumber) {
      return res.status(400).json({ message: "All fields required" });
    }

    if (!PHONE_REGEX.test(phoneNumber)) {
      return res.status(400).json({ message: "Invalid phone number" });
    }

    const existing = await User.findOne({
      $or: [{ username }, { phoneNumber }],
    });

    if (existing) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await User.create({
      username,
      phoneNumber,
      password: hashedPassword,
    });

    res.status(201).json({
      message: "Signup successful",
      userId: user._id,
      username: user.username,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ message: "Invalid credentials" });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ message: "Invalid credentials" });

    const token = jwt.sign(
      { userId: user._id.toString(), username: user.username },
      JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({
      token,
      userId: user._id,
      username: user.username,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Internal server error" });
  }
});

// -------------------- OTP --------------------
app.post("/auth/request-otp", async (req, res) => {
  try {
    const { phoneNumber } = req.body;

    if (!PHONE_REGEX.test(phoneNumber)) {
      return res.status(400).json({ message: "Invalid phone number" });
    }

    const user = await User.findOne({ phoneNumber });
    if (!user) return res.status(404).json({ message: "User not found" });

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const hash = await bcrypt.hash(code, 10);

    await Otp.create({
      phoneNumber,
      codeHash: hash,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000),
      used: false,
    });

    console.log("OTP:", code);
    res.json({ message: "OTP sent (dev mode)" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/auth/verify-otp", async (req, res) => {
  try {
    const { phoneNumber, code } = req.body;

    const otp = await Otp.findOne({ phoneNumber }).sort({ createdAt: -1 });
    if (!otp || otp.used || otp.expiresAt < new Date()) {
      return res.status(400).json({ message: "Invalid OTP" });
    }

    const ok = await bcrypt.compare(code, otp.codeHash);
    if (!ok) return res.status(400).json({ message: "Invalid OTP" });

    otp.used = true;
    await otp.save();

    const user = await User.findOne({ phoneNumber });
    if (!user) return res.status(404).json({ message: "User not found" });

    const token = jwt.sign(
      { userId: user._id.toString(), username: user.username },
      JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({
      token,
      userId: user._id,
      username: user.username,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Internal server error" });
  }
});

// -------------------- CONVERSATIONS --------------------
app.get("/conversations/:userId", authMiddleware, async (req, res) => {
  try {
    const conversations = await Conversation.find({
      participants: req.params.userId,
    });

    const enriched = [];
    for (const c of conversations) {
      const otherId = c.participants.find(
        (p) => p.toString() !== req.params.userId
      );
      const other = await User.findById(otherId);
      enriched.push({
        _id: c._id,
        otherUserId: otherId,
        otherUsername: other?.username || "Unknown",
      });
    }

    res.json({ conversations: enriched });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/conversations/by-phone", authMiddleware, async (req, res) => {
  try {
    const { myUserId, otherPhone } = req.body;

    const other = await User.findOne({ phoneNumber: otherPhone });
    if (!other) return res.status(404).json({ message: "User not found" });

    let convo = await Conversation.findOne({
      participants: { $all: [myUserId, other._id] },
    });

    if (!convo) {
      convo = await Conversation.create({
        participants: [myUserId, other._id],
      });
    }

    res.json({
      conversationId: convo._id,
      otherUserId: other._id,
      otherUsername: other.username,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Internal server error" });
  }
});

// -------------------- MESSAGES --------------------
app.post("/messages", authMiddleware, async (req, res) => {
  try {
    const { conversationId, ciphertext, iv } = req.body;
    const senderId = req.user?.userId;

    if (!senderId) return res.status(401).json({ message: "Unauthorized" });

    // optional safety check (prevents sending to random convoId)
    const convo = await Conversation.findById(conversationId);
    if (!convo) return res.status(404).json({ message: "Conversation not found" });

    const msg = await Message.create({
      conversationId,
      senderId,
      ciphertext,
      iv,
    });

    // ✅ IMPORTANT: emit to room = conversationId
    io.to(conversationId.toString()).emit("newMessage", msg);

    res.status(201).json({ data: msg });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/messages", authMiddleware, async (req, res) => {
  try {
    const messages = await Message.find({
      conversationId: req.query.conversationId,
    }).sort({ createdAt: 1 });

    res.json({ messages });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Internal server error" });
  }
});

// -------------------- SOCKET EVENTS --------------------
const onlineUsers = new Map();

io.on("connection", (socket) => {
  console.log("✅ socket connected:", socket.id);

  socket.on("registerUser", (userId) => {
    if (!userId) return;

    if (!onlineUsers.has(userId)) onlineUsers.set(userId, new Set());
    onlineUsers.get(userId).add(socket.id);

    socket.join(userId); // ✅ user room (optional but useful)
    io.emit("presenceUpdate", { userId, online: true });
  });

  // ✅ KEY FIX: joinConversation MUST be called from frontend when opening a chat
  socket.on("joinConversation", (conversationId) => {
    if (!conversationId) return;
    socket.join(conversationId.toString());
    console.log("✅ joined conversation room:", conversationId);
  });

  // OPTIONAL: if you later want to send via socket instead of REST
  socket.on("sendMessage", async ({ conversationId, ciphertext, iv, senderId }) => {
    try {
      if (!conversationId || !ciphertext || !iv || !senderId) return;

      const msg = await Message.create({ conversationId, senderId, ciphertext, iv });
      io.to(conversationId.toString()).emit("newMessage", msg);
    } catch (e) {
      console.error("sendMessage socket error:", e);
    }
  });

  socket.on("disconnect", () => {
    for (const [userId, sockets] of onlineUsers) {
      sockets.delete(socket.id);
      if (sockets.size === 0) {
        onlineUsers.delete(userId);
        io.emit("presenceUpdate", { userId, online: false });
      }
    }
    console.log("❌ socket disconnected:", socket.id);
  });
});

// -------------------- START --------------------
const PORT = process.env.PORT || 4000;
server.listen(PORT, () => {
  console.log("Server running on port", PORT);
});
