require("dotenv").config();
const http = require("http");
const crypto = require("crypto");
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const { Server } = require("socket.io");

const { MONGO_URI, JWT_SECRET, PORT = 3000 } = process.env;
if (!MONGO_URI || !JWT_SECRET) throw new Error("Set MONGO_URI and JWT_SECRET in .env");

const EXPIRY_MS = 5 * 60 * 1000; // messages vanish 5 min after being read
const MAX_TEXT = 4000;

/* ---------- Models ---------- */
const userSchema = new mongoose.Schema({
  chatId: { type: String, unique: true, index: true },
  username: { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true },
  pushToken: String,
});
const User = mongoose.model("User", userSchema);

const requestSchema = new mongoose.Schema(
  {
    from: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    to: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    status: { type: String, enum: ["pending", "accepted", "declined"], default: "pending" },
  },
  { timestamps: true }
);
requestSchema.index({ from: 1, to: 1 }, { unique: true });
const ChatRequest = mongoose.model("ChatRequest", requestSchema);

const messageSchema = new mongoose.Schema({
  pair: { type: String, index: true },
  from: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  to: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  kind: { type: String, enum: ["text", "image", "video", "audio", "file"], default: "text" },
  text: { type: String, maxlength: MAX_TEXT, default: "" }, // message text, or caption for media
  // Media fields (filePath is never sent to clients)
  filePath: String,
  fileName: String,
  mime: String,
  size: Number,
  createdAt: { type: Date, default: Date.now },
  readAt: Date,
  // Set only when read. The sweeper below deletes the message AND its file once this passes.
  expireAt: { type: Date, index: true },
});
messageSchema.set("toJSON", {
  transform: (_doc, ret) => {
    delete ret.filePath;
    return ret;
  },
});
const Message = mongoose.model("Message", messageSchema);

/* ---------- Media storage ---------- */
const UPLOAD_DIR = path.join(__dirname, "uploads");
fs.mkdirSync(UPLOAD_DIR, { recursive: true });
const MAX_FILE_BYTES = 25 * 1024 * 1024; // 25 MB
const ALLOWED = {
  "image/jpeg": "image",
  "image/png": "image",
  "image/webp": "image",
  "image/gif": "image",
  "video/mp4": "video",
  "video/quicktime": "video",
  "audio/mpeg": "audio",
  "audio/mp4": "audio",
  "audio/aac": "audio",
  "audio/x-m4a": "audio",
  "application/pdf": "file",
};
const upload = multer({
  storage: multer.diskStorage({
    destination: UPLOAD_DIR,
    filename: (_req, _file, cb) => cb(null, crypto.randomBytes(16).toString("hex")),
  }),
  limits: { fileSize: MAX_FILE_BYTES, files: 1 },
  fileFilter: (_req, file, cb) =>
    ALLOWED[file.mimetype] ? cb(null, true) : cb(new Error("File type not allowed")),
});
const removeFile = (p) => p && fs.unlink(p, () => {});

/* ---------- Helpers ---------- */
const ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"; // no look-alike characters
function makeChatId(len = 8) {
  const bytes = crypto.randomBytes(len);
  return Array.from(bytes, (b) => ALPHABET[b % ALPHABET.length]).join("");
}
const pairKey = (a, b) => [String(a), String(b)].sort().join(":");
const sign = (user) => jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "30d" });

async function areConnected(a, b) {
  const r = await ChatRequest.findOne({
    status: "accepted",
    $or: [
      { from: a, to: b },
      { from: b, to: a },
    ],
  }).lean();
  return !!r;
}

function auth(req, res, next) {
  try {
    const token = (req.headers.authorization || "").replace("Bearer ", "");
    req.userId = jwt.verify(token, JWT_SECRET).id;
    next();
  } catch {
    res.status(401).json({ error: "Unauthorized" });
  }
}

/* ---------- App ---------- */
const app = express();
app.use(express.json({ limit: "20kb" }));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30 });
const lookupLimiter = rateLimit({ windowMs: 60 * 1000, max: 10 }); // slows chat-ID guessing

app.post("/auth/register", authLimiter, async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password || password.length < 8)
    return res.status(400).json({ error: "Username and a password of 8+ characters required" });
  try {
    let user;
    for (let i = 0; i < 5 && !user; i++) {
      try {
        user = await User.create({
          username,
          passwordHash: await bcrypt.hash(password, 12),
          chatId: makeChatId(),
        });
      } catch (e) {
        if (e.code === 11000 && e.keyPattern?.username)
          return res.status(409).json({ error: "Username taken" });
        if (e.code !== 11000) throw e; // chatId collision: retry
      }
    }
    res.json({ token: sign(user), chatId: user.chatId });
  } catch (e) {
    res.status(500).json({ error: "Could not register" });
  }
});

app.post("/auth/login", authLimiter, async (req, res) => {
  const { username, password } = req.body || {};
  const user = await User.findOne({ username: String(username || "").toLowerCase() });
  if (!user || !(await bcrypt.compare(password || "", user.passwordHash)))
    return res.status(401).json({ error: "Invalid credentials" });
  res.json({ token: sign(user), chatId: user.chatId });
});

app.get("/me", auth, async (req, res) => {
  const u = await User.findById(req.userId).select("chatId username");
  res.json(u);
});

app.post("/me/push-token", auth, async (req, res) => {
  await User.updateOne({ _id: req.userId }, { pushToken: String(req.body.token || "") });
  res.json({ ok: true });
});

// Send a chat request using only the other person's chat ID
app.post("/requests", auth, lookupLimiter, async (req, res) => {
  const target = await User.findOne({ chatId: String(req.body.chatId || "").toLowerCase() });
  if (!target) return res.status(404).json({ error: "No user with that chat ID" });
  if (String(target._id) === req.userId)
    return res.status(400).json({ error: "You can't add yourself" });

  const existing = await ChatRequest.findOne({
    $or: [
      { from: req.userId, to: target._id },
      { from: target._id, to: req.userId },
    ],
  });
  if (existing) return res.status(409).json({ error: `Request already ${existing.status}` });

  const reqDoc = await ChatRequest.create({ from: req.userId, to: target._id });
  const me = await User.findById(req.userId).select("chatId username");
  io.to(`user:${target._id}`).emit("request:new", { id: reqDoc._id, from: me });
  res.json({ id: reqDoc._id, status: "pending" });
});

app.get("/requests/incoming", auth, async (req, res) => {
  const list = await ChatRequest.find({ to: req.userId, status: "pending" })
    .populate("from", "chatId username")
    .sort({ createdAt: -1 });
  res.json(list);
});

app.post("/requests/:id/respond", auth, async (req, res) => {
  const accept = !!req.body.accept;
  const r = await ChatRequest.findOneAndUpdate(
    { _id: req.params.id, to: req.userId, status: "pending" },
    { status: accept ? "accepted" : "declined" },
    { new: true }
  );
  if (!r) return res.status(404).json({ error: "Request not found" });
  io.to(`user:${r.from}`).emit("request:responded", { id: r._id, status: r.status });
  res.json({ status: r.status });
});

app.get("/contacts", auth, async (req, res) => {
  const list = await ChatRequest.find({
    status: "accepted",
    $or: [{ from: req.userId }, { to: req.userId }],
  })
    .populate("from to", "chatId username")
    .lean();
  res.json(
    list.map((r) => (String(r.from._id) === req.userId ? r.to : r.from))
  );
});

app.get("/messages/:contactId", auth, async (req, res) => {
  if (!(await areConnected(req.userId, req.params.contactId)))
    return res.status(403).json({ error: "Not connected" });
  const msgs = await Message.find({
    pair: pairKey(req.userId, req.params.contactId),
    $or: [{ expireAt: { $exists: false } }, { expireAt: { $gt: new Date() } }], // TTL can lag ~60s
  })
    .sort({ createdAt: 1 })
    .limit(200);
  res.json(msgs);
});

// Send a photo / video / voice note / PDF (multipart: file, to, optional text caption)
app.post(
  "/messages/media",
  auth,
  (req, res, next) =>
    upload.single("file")(req, res, (err) =>
      err ? res.status(400).json({ error: err.message }) : next()
    ),
  async (req, res) => {
    const file = req.file;
    try {
      if (!file) return res.status(400).json({ error: "No file" });
      const to = req.body.to;
      if (!mongoose.isValidObjectId(to) || !(await areConnected(req.userId, to))) {
        removeFile(file.path);
        return res.status(403).json({ error: "Chat request not accepted" });
      }
      const msg = await Message.create({
        pair: pairKey(req.userId, to),
        from: req.userId,
        to,
        kind: ALLOWED[file.mimetype],
        text: String(req.body.text || "").slice(0, MAX_TEXT),
        filePath: file.path,
        fileName: path.basename(file.originalname || "file").slice(0, 120),
        mime: file.mimetype,
        size: file.size,
      });
      io.to(`user:${to}`).emit("message:new", msg);
      res.json(msg);
    } catch {
      if (file) removeFile(file.path);
      res.status(500).json({ error: "Upload failed" });
    }
  }
);

// Media is never served statically: only the sender/recipient can fetch it, and only until it expires
app.get("/media/:messageId", auth, async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.messageId)) return res.sendStatus(404);
  const msg = await Message.findById(req.params.messageId);
  const mine = msg && [String(msg.from), String(msg.to)].includes(req.userId);
  if (!mine || !msg.filePath || (msg.expireAt && msg.expireAt <= new Date()))
    return res.sendStatus(404);
  res.setHeader("Content-Type", msg.mime);
  res.setHeader("Cache-Control", "no-store");
  res.sendFile(msg.filePath);
});

/* ---------- Real-time ---------- */
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

io.use((socket, next) => {
  try {
    socket.userId = jwt.verify(socket.handshake.auth?.token, JWT_SECRET).id;
    next();
  } catch {
    next(new Error("Unauthorized"));
  }
});

io.on("connection", (socket) => {
  socket.join(`user:${socket.userId}`);

  // { to: <contact user _id>, text }
  socket.on("message:send", async ({ to, text } = {}, ack) => {
    try {
      if (!text || typeof text !== "string" || text.length > MAX_TEXT)
        return ack?.({ error: "Invalid message" });
      // Server-side gate: no accepted request, no messaging
      if (!(await areConnected(socket.userId, to)))
        return ack?.({ error: "Chat request not accepted" });
      const msg = await Message.create({
        pair: pairKey(socket.userId, to),
        from: socket.userId,
        to,
        text,
      });
      io.to(`user:${to}`).emit("message:new", msg);
      ack?.({ ok: true, message: msg });
    } catch {
      ack?.({ error: "Send failed" });
    }
  });

  // { ids: [messageId, ...] } sent by the recipient when messages are viewed
  socket.on("message:read", async ({ ids } = {}, ack) => {
    try {
      const readAt = new Date();
      const expireAt = new Date(readAt.getTime() + EXPIRY_MS);
      const msgs = await Message.find({ _id: { $in: ids || [] }, to: socket.userId, readAt: null });
      if (!msgs.length) return ack?.({ ok: true });
      await Message.updateMany(
        { _id: { $in: msgs.map((m) => m._id) } },
        { readAt, expireAt }
      );
      const senders = [...new Set(msgs.map((m) => String(m.from)))];
      const payload = { ids: msgs.map((m) => m._id), readAt, expireAt };
      senders.forEach((s) => io.to(`user:${s}`).emit("message:read", payload));
      ack?.({ ok: true, ...payload });
    } catch {
      ack?.({ error: "Read update failed" });
    }
  });

  // Client reports it detected a screenshot / screen recording. { to, type }
  socket.on("security:alert", async ({ to, type } = {}) => {
    if (!["screenshot", "screen_recording"].includes(type)) return;
    if (!(await areConnected(socket.userId, to))) return;
    const me = await User.findById(socket.userId).select("chatId username");
    io.to(`user:${to}`).emit("security:alert", { from: me, type, at: new Date() });
    // TODO: also send an FCM push so the alert arrives when the recipient's app is closed
  });
});

// Deletes messages (and their media files) 5 minutes after they were read.
// Runs often so expiry is near-exact; clients also hide messages locally at expireAt.
async function sweepExpired() {
  try {
    const expired = await Message.find({ expireAt: { $lte: new Date() } }).select("_id filePath from to");
    if (!expired.length) return;
    expired.forEach((m) => removeFile(m.filePath));
    await Message.deleteMany({ _id: { $in: expired.map((m) => m._id) } });
    const ids = expired.map((m) => m._id);
    const users = new Set(expired.flatMap((m) => [String(m.from), String(m.to)]));
    users.forEach((u) => io.to(`user:${u}`).emit("message:expired", { ids }));
  } catch (e) {
    console.error("Sweep failed", e.message);
  }
}

mongoose.connect(MONGO_URI).then(() => {
  setInterval(sweepExpired, 15 * 1000);
  server.listen(PORT, () => console.log(`Server running on :${PORT}`));
});
