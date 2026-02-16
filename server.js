const express = require("express");
const cookieParser = require("cookie-parser");
const path = require("path");
const crypto = require("crypto");
const sqlite3 = require("sqlite3").verbose();
const { Server } = require("socket.io");
const http = require("http");

const PORT = process.env.PORT || 3000;
const IS_VERCEL = Boolean(process.env.VERCEL);
const DB_PATH = IS_VERCEL ? ":memory:" : path.join(__dirname, "data", "applyo.db");
const RATE_LIMIT_DISABLED = process.env.DISABLE_RATE_LIMIT === "1";

const SLUG_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789";
const ADMIN_TOKEN_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

function generateFromAlphabet(length, alphabet) {
  let value = "";
  for (let i = 0; i < length; i += 1) {
    value += alphabet[crypto.randomInt(0, alphabet.length)];
  }
  return value;
}

function slugGenerator() {
  return generateFromAlphabet(8, SLUG_ALPHABET);
}

function adminTokenGenerator() {
  return generateFromAlphabet(24, ADMIN_TOKEN_ALPHABET);
}

let dbFatalError = null;
const db = new sqlite3.Database(DB_PATH, (error) => {
  if (error) {
    dbFatalError = error;
    console.error("SQLite open error:", error);
  }
});
db.on("error", (error) => {
  dbFatalError = error;
  console.error("SQLite runtime error:", error);
});
const app = express();
const server = IS_VERCEL ? null : http.createServer(app);
const io = IS_VERCEL
  ? { to: () => ({ emit: () => {} }), on: () => {} }
  : new Server(server);

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

app.use((_req, res, next) => {
  if (dbFatalError) {
    return res.status(500).json({ error: "Database is not available in this environment." });
  }
  return next();
});

function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function onRun(err) {
      if (err) return reject(err);
      resolve(this);
    });
  });
}

function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row);
    });
  });
}

function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows);
    });
  });
}

function normalizeClientIp(req) {
  const raw = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").toString();
  return raw.split(",")[0].trim();
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(password, storedHash) {
  const [salt, savedHash] = String(storedHash || "").split(":");
  if (!salt || !savedHash) return false;
  const calculatedHash = crypto.scryptSync(password, salt, 64).toString("hex");
  return crypto.timingSafeEqual(Buffer.from(savedHash, "hex"), Buffer.from(calculatedHash, "hex"));
}

function userVoteKey(userId) {
  return `user:${userId}`;
}

async function setupDatabase() {
  await run("PRAGMA foreign_keys = ON;");

  await run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      token TEXT NOT NULL UNIQUE,
      user_id INTEGER NOT NULL,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS polls (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      slug TEXT NOT NULL UNIQUE,
      admin_token TEXT,
      question TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      created_by_ip TEXT,
      created_by_user_id INTEGER,
      FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE SET NULL
    );
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS options (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      poll_id INTEGER NOT NULL,
      text TEXT NOT NULL,
      FOREIGN KEY (poll_id) REFERENCES polls(id) ON DELETE CASCADE
    );
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS votes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      poll_id INTEGER NOT NULL,
      option_id INTEGER NOT NULL,
      device_id TEXT NOT NULL,
      user_id INTEGER,
      voter_ip TEXT,
      created_at INTEGER NOT NULL,
      UNIQUE (poll_id, device_id),
      FOREIGN KEY (poll_id) REFERENCES polls(id) ON DELETE CASCADE,
      FOREIGN KEY (option_id) REFERENCES options(id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
    );
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS rate_limits (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ip TEXT NOT NULL,
      action TEXT NOT NULL,
      poll_id INTEGER,
      created_at INTEGER NOT NULL
    );
  `);

  const pollColumns = await all("PRAGMA table_info(polls);");
  if (!pollColumns.some((column) => column.name === "admin_token")) {
    await run("ALTER TABLE polls ADD COLUMN admin_token TEXT;");
  }
  if (!pollColumns.some((column) => column.name === "created_by_user_id")) {
    await run("ALTER TABLE polls ADD COLUMN created_by_user_id INTEGER;");
  }

  const voteColumns = await all("PRAGMA table_info(votes);");
  if (!voteColumns.some((column) => column.name === "user_id")) {
    await run("ALTER TABLE votes ADD COLUMN user_id INTEGER;");
  }

  const pollsWithoutToken = await all("SELECT id FROM polls WHERE admin_token IS NULL OR admin_token = '';");
  for (const poll of pollsWithoutToken) {
    let adminToken = adminTokenGenerator();
    while (await get("SELECT id FROM polls WHERE admin_token = ?", [adminToken])) {
      adminToken = adminTokenGenerator();
    }
    await run("UPDATE polls SET admin_token = ? WHERE id = ?", [adminToken, poll.id]);
  }

  await run("CREATE INDEX IF NOT EXISTS idx_polls_slug ON polls(slug);");
  await run("CREATE UNIQUE INDEX IF NOT EXISTS idx_polls_admin_token ON polls(admin_token);");
  await run("CREATE INDEX IF NOT EXISTS idx_polls_creator ON polls(created_by_user_id);");
  await run("CREATE INDEX IF NOT EXISTS idx_votes_poll_option ON votes(poll_id, option_id);");
  await run("CREATE INDEX IF NOT EXISTS idx_votes_poll_device ON votes(poll_id, device_id);");
  await run("CREATE INDEX IF NOT EXISTS idx_votes_poll_user ON votes(poll_id, user_id);");
  await run("CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);");
  await run("CREATE INDEX IF NOT EXISTS idx_rate_limits_lookup ON rate_limits(ip, action, poll_id, created_at);");
}

const dbReady = setupDatabase();

app.use("/api", async (_req, res, next) => {
  try {
    await dbReady;
    next();
  } catch (error) {
    console.error("Database setup failed:", error);
    res.status(500).json({ error: "Database initialization failed." });
  }
});

async function enforceRateLimit(ip, action, pollId, windowMs, maxHits) {
  if (RATE_LIMIT_DISABLED) return true;

  const now = Date.now();
  const cutoff = now - windowMs;

  await run("DELETE FROM rate_limits WHERE created_at < ?", [now - 1000 * 60 * 60 * 48]);

  const row = await get(
    `SELECT COUNT(*) AS count
     FROM rate_limits
     WHERE ip = ? AND action = ? AND (poll_id IS ? OR poll_id = ?) AND created_at >= ?`,
    [ip, action, pollId ?? null, pollId ?? null, cutoff]
  );

  if (row && row.count >= maxHits) return false;

  await run("INSERT INTO rate_limits (ip, action, poll_id, created_at) VALUES (?, ?, ?, ?)", [
    ip,
    action,
    pollId ?? null,
    now
  ]);
  return true;
}

async function createSession(res, userId) {
  const token = crypto.randomBytes(32).toString("hex");
  const now = Date.now();
  const expiresAt = now + 1000 * 60 * 60 * 24 * 7;
  await run("INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)", [
    token,
    userId,
    now,
    expiresAt
  ]);
  res.cookie("sid", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 1000 * 60 * 60 * 24 * 7
  });
}

app.use(async (req, _res, next) => {
  try {
    req.user = null;
    const sid = req.cookies.sid;
    if (!sid) return next();

    const session = await get(
      `
      SELECT s.token, s.expires_at, u.id, u.name, u.email
      FROM sessions s
      INNER JOIN users u ON u.id = s.user_id
      WHERE s.token = ?
    `,
      [sid]
    );
    if (!session || Number(session.expires_at) < Date.now()) {
      return next();
    }
    req.user = {
      id: session.id,
      name: session.name,
      email: session.email
    };
    return next();
  } catch (error) {
    return next();
  }
});

function requireAuth(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: "Login required." });
  }
  return next();
}

function normalizePollInput(body) {
  const question = typeof body.question === "string" ? body.question.trim() : "";
  const rawOptions = Array.isArray(body.options) ? body.options : [];
  const options = rawOptions
    .map((option) => (typeof option === "string" ? option.trim() : ""))
    .filter(Boolean);
  return { question, options };
}

function validatePollInput(question, options) {
  if (!question || question.length < 5 || question.length > 200) {
    return "Question must be between 5 and 200 characters.";
  }
  if (options.length < 2 || options.length > 8) {
    return "Poll must contain between 2 and 8 options.";
  }
  if (options.some((option) => option.length < 1 || option.length > 80)) {
    return "Each option must be between 1 and 80 characters.";
  }
  const deduped = new Set(options.map((option) => option.toLowerCase()));
  if (deduped.size !== options.length) {
    return "Options must be unique.";
  }
  return null;
}

async function getPollStatsById(pollId) {
  const options = await all(
    `
      SELECT
        o.id,
        o.text,
        COALESCE(COUNT(v.id), 0) AS votes
      FROM options o
      LEFT JOIN votes v ON v.option_id = o.id
      WHERE o.poll_id = ?
      GROUP BY o.id
      ORDER BY o.id ASC
    `,
    [pollId]
  );
  const totalVotes = options.reduce((sum, row) => sum + Number(row.votes), 0);
  return { options, totalVotes };
}

async function getPollBySlug(slug) {
  return get(
    `
      SELECT p.id, p.slug, p.question, p.created_at, p.admin_token, u.id AS creator_id, u.name AS creator_name, u.email AS creator_email
      FROM polls p
      LEFT JOIN users u ON u.id = p.created_by_user_id
      WHERE p.slug = ?
    `,
    [slug]
  );
}

app.post("/api/auth/signup", async (req, res) => {
  try {
    const name = typeof req.body.name === "string" ? req.body.name.trim() : "";
    const email = typeof req.body.email === "string" ? req.body.email.trim().toLowerCase() : "";
    const password = typeof req.body.password === "string" ? req.body.password : "";

    if (!name || name.length < 2 || name.length > 80) {
      return res.status(400).json({ error: "Name must be between 2 and 80 characters." });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: "Valid email is required." });
    }
    if (password.length < 6 || password.length > 120) {
      return res.status(400).json({ error: "Password must be between 6 and 120 characters." });
    }

    const existingUser = await get("SELECT id FROM users WHERE email = ?", [email]);
    if (existingUser) {
      return res.status(409).json({ error: "Email already registered." });
    }

    const insert = await run("INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, ?)", [
      name,
      email,
      hashPassword(password),
      Date.now()
    ]);

    await createSession(res, insert.lastID);
    return res.status(201).json({ user: { id: insert.lastID, name, email } });
  } catch (error) {
    return res.status(500).json({ error: "Could not create account." });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const email = typeof req.body.email === "string" ? req.body.email.trim().toLowerCase() : "";
    const password = typeof req.body.password === "string" ? req.body.password : "";
    const user = await get("SELECT id, name, email, password_hash FROM users WHERE email = ?", [email]);
    if (!user || !verifyPassword(password, user.password_hash)) {
      return res.status(401).json({ error: "Invalid email or password." });
    }
    await createSession(res, user.id);
    return res.json({ user: { id: user.id, name: user.name, email: user.email } });
  } catch (error) {
    return res.status(500).json({ error: "Could not login." });
  }
});

app.post("/api/auth/logout", async (req, res) => {
  try {
    if (req.cookies.sid) {
      await run("DELETE FROM sessions WHERE token = ?", [req.cookies.sid]);
    }
    res.clearCookie("sid");
    return res.status(204).send();
  } catch (error) {
    return res.status(500).json({ error: "Could not logout." });
  }
});

app.get("/api/auth/me", (req, res) => {
  if (!req.user) return res.status(401).json({ error: "Not logged in." });
  return res.json({ user: req.user });
});

app.get("/api/dashboard", requireAuth, async (req, res) => {
  try {
    const myPolls = await all(
      `
      SELECT p.slug, p.question, p.created_at, p.admin_token, COALESCE(COUNT(v.id), 0) AS total_votes
      FROM polls p
      LEFT JOIN votes v ON v.poll_id = p.id
      WHERE p.created_by_user_id = ?
      GROUP BY p.id
      ORDER BY p.created_at DESC
    `,
      [req.user.id]
    );

    const myVotes = await all(
      `
      SELECT p.slug, p.question, o.text AS selected_option, v.created_at
      FROM votes v
      INNER JOIN polls p ON p.id = v.poll_id
      INNER JOIN options o ON o.id = v.option_id
      WHERE v.user_id = ?
      ORDER BY v.created_at DESC
    `,
      [req.user.id]
    );

    const allPolls = await all(
      `
      SELECT p.slug, p.question, p.created_at, u.name AS creator_name, u.email AS creator_email, COALESCE(COUNT(v.id), 0) AS total_votes
      FROM polls p
      LEFT JOIN users u ON u.id = p.created_by_user_id
      LEFT JOIN votes v ON v.poll_id = p.id
      GROUP BY p.id
      ORDER BY p.created_at DESC
      LIMIT 100
    `
    );

    return res.json({
      user: req.user,
      myPolls: myPolls.map((p) => ({
        ...p,
        totalVotes: Number(p.total_votes),
        adminUrl: `${req.protocol}://${req.get("host")}/admin/${p.slug}?token=${encodeURIComponent(p.admin_token)}`
      })),
      myVotes,
      allPolls: allPolls.map((p) => ({ ...p, totalVotes: Number(p.total_votes) }))
    });
  } catch (error) {
    return res.status(500).json({ error: "Could not load dashboard." });
  }
});

app.post("/api/polls", requireAuth, async (req, res) => {
  try {
    const ip = normalizeClientIp(req);
    const allowed = await enforceRateLimit(ip, "create", null, 1000 * 60 * 60, 10);
    if (!allowed) {
      return res.status(429).json({ error: "Too many polls created from this IP. Please try again later." });
    }

    const { question, options } = normalizePollInput(req.body);
    const validationError = validatePollInput(question, options);
    if (validationError) return res.status(400).json({ error: validationError });

    let slug = slugGenerator();
    while (await get("SELECT id FROM polls WHERE slug = ?", [slug])) {
      slug = slugGenerator();
    }

    let adminToken = adminTokenGenerator();
    while (await get("SELECT id FROM polls WHERE admin_token = ?", [adminToken])) {
      adminToken = adminTokenGenerator();
    }

    const pollInsert = await run(
      "INSERT INTO polls (slug, admin_token, question, created_at, created_by_ip, created_by_user_id) VALUES (?, ?, ?, ?, ?, ?)",
      [slug, adminToken, question, Date.now(), ip, req.user.id]
    );
    const pollId = pollInsert.lastID;

    for (const option of options) {
      await run("INSERT INTO options (poll_id, text) VALUES (?, ?)", [pollId, option]);
    }

    const shareUrl = `${req.protocol}://${req.get("host")}/poll/${slug}`;
    const adminUrl = `${req.protocol}://${req.get("host")}/admin/${slug}?token=${encodeURIComponent(adminToken)}`;
    return res.status(201).json({ slug, shareUrl, adminUrl });
  } catch (error) {
    return res.status(500).json({ error: "Could not create poll." });
  }
});

app.get("/api/polls/:slug", async (req, res) => {
  try {
    const poll = await getPollBySlug(req.params.slug);
    if (!poll) return res.status(404).json({ error: "Poll not found." });

    const voteRecord = req.user
      ? await get("SELECT option_id FROM votes WHERE poll_id = ? AND device_id = ?", [poll.id, userVoteKey(req.user.id)])
      : null;
    const stats = await getPollStatsById(poll.id);

    return res.json({
      poll: {
        slug: poll.slug,
        question: poll.question,
        createdAt: poll.created_at,
        createdBy: poll.creator_name
          ? { id: poll.creator_id, name: poll.creator_name, email: poll.creator_email }
          : null
      },
      options: stats.options.map((option) => ({
        id: option.id,
        text: option.text,
        votes: Number(option.votes)
      })),
      totalVotes: stats.totalVotes,
      hasVoted: Boolean(voteRecord),
      userOptionId: voteRecord ? voteRecord.option_id : null
    });
  } catch (error) {
    return res.status(500).json({ error: "Could not fetch poll." });
  }
});

app.post("/api/polls/:slug/vote", requireAuth, async (req, res) => {
  try {
    const ip = normalizeClientIp(req);
    const optionId = Number(req.body.optionId);
    if (!Number.isInteger(optionId)) return res.status(400).json({ error: "Valid optionId is required." });

    const poll = await getPollBySlug(req.params.slug);
    if (!poll) return res.status(404).json({ error: "Poll not found." });

    const allowed = await enforceRateLimit(ip, "vote", poll.id, 1000 * 60, 40);
    if (!allowed) {
      return res.status(429).json({ error: "Too many vote attempts from this IP. Please wait and retry." });
    }

    const option = await get("SELECT id FROM options WHERE id = ? AND poll_id = ?", [optionId, poll.id]);
    if (!option) return res.status(400).json({ error: "Invalid option for this poll." });

    try {
      await run(
        "INSERT INTO votes (poll_id, option_id, device_id, user_id, voter_ip, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        [poll.id, optionId, userVoteKey(req.user.id), req.user.id, ip, Date.now()]
      );
    } catch (error) {
      if (error && error.code === "SQLITE_CONSTRAINT") {
        return res.status(409).json({ error: "You already voted in this poll." });
      }
      throw error;
    }

    const stats = await getPollStatsById(poll.id);
    const payload = {
      slug: poll.slug,
      options: stats.options.map((row) => ({
        id: row.id,
        text: row.text,
        votes: Number(row.votes)
      })),
      totalVotes: stats.totalVotes
    };
    io.to(`poll:${poll.slug}`).emit("poll:update", payload);
    return res.status(201).json(payload);
  } catch (error) {
    return res.status(500).json({ error: "Could not record vote." });
  }
});

app.get("/api/admin/polls/:slug", async (req, res) => {
  try {
    const token = typeof req.query.token === "string" ? req.query.token : "";
    if (!token) return res.status(401).json({ error: "Admin token is required." });

    const poll = await get(
      `
      SELECT p.id, p.slug, p.question, p.created_at, u.name AS creator_name, u.email AS creator_email
      FROM polls p
      LEFT JOIN users u ON u.id = p.created_by_user_id
      WHERE p.slug = ? AND p.admin_token = ?
    `,
      [req.params.slug, token]
    );
    if (!poll) return res.status(403).json({ error: "Invalid admin credentials for this poll." });

    const votes = await all(
      `
      SELECT
        v.id,
        v.created_at,
        o.text AS option_text,
        u.name AS voter_name,
        u.email AS voter_email
      FROM votes v
      INNER JOIN options o ON o.id = v.option_id
      LEFT JOIN users u ON u.id = v.user_id
      WHERE v.poll_id = ?
      ORDER BY v.created_at ASC
    `,
      [poll.id]
    );

    return res.json({
      poll: {
        slug: poll.slug,
        question: poll.question,
        createdAt: poll.created_at,
        creatorName: poll.creator_name,
        creatorEmail: poll.creator_email
      },
      votes: votes.map((vote) => ({
        id: vote.id,
        optionText: vote.option_text,
        voterName: vote.voter_name || "Unknown",
        voterEmail: vote.voter_email || "Unknown",
        createdAt: vote.created_at
      }))
    });
  } catch (error) {
    return res.status(500).json({ error: "Could not fetch admin poll data." });
  }
});

app.get("/", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/login", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.get("/signup", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "signup.html"));
});

app.get("/poll/:slug", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "poll.html"));
});

app.get("/admin/:slug", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});

app.get("/create-poll", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "create-poll.html"));
});

app.get("/my-polls", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "my-polls.html"));
});

app.get("/my-votes", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "my-votes.html"));
});

app.get("/browse-polls", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "browse-polls.html"));
});

if (!IS_VERCEL) {
  io.on("connection", (socket) => {
    socket.on("poll:join", (slug) => {
      if (typeof slug !== "string" || slug.length > 64) return;
      socket.join(`poll:${slug}`);
    });
  });
}

if (!IS_VERCEL) {
  dbReady
    .then(() => {
      server.listen(PORT, () => {
        console.log(`Server running on http://localhost:${PORT}`);
      });
    })
    .catch((error) => {
      console.error("Database setup failed:", error);
      process.exit(1);
    });
}

module.exports = app;
