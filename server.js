import "dotenv/config";
import bcrypt from "bcryptjs";
import crypto from "node:crypto";
import express from "express";
import jwt from "jsonwebtoken";
import mysql from "mysql2/promise";
import nodemailer from "nodemailer";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = Number(process.env.PORT || 3000);
const appUrl = (process.env.APP_URL || `http://localhost:${port}`).replace(/\/$/, "");

const requiredEnv = ["MYSQL_HOST", "MYSQL_DATABASE", "MYSQL_USER", "MYSQL_PASSWORD", "JWT_SECRET"];
const missingEnv = requiredEnv.filter((key) => !process.env[key]);

if (missingEnv.length) {
  throw new Error(`Missing required environment variables: ${missingEnv.join(", ")}`);
}

const pool = mysql.createPool({
  host: process.env.MYSQL_HOST,
  port: Number(process.env.MYSQL_PORT || 3306),
  database: process.env.MYSQL_DATABASE,
  user: process.env.MYSQL_USER,
  password: process.env.MYSQL_PASSWORD,
  ssl: process.env.MYSQL_SSL === "true" ? { minVersion: "TLSv1.2" } : undefined,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

app.use((request, response, next) => {
  response.setHeader("Access-Control-Allow-Origin", request.headers.origin || "*");
  response.setHeader("Vary", "Origin");
  response.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  response.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

  if (request.method === "OPTIONS") {
    return response.sendStatus(204);
  }

  next();
});

app.use(express.json({ limit: "100kb" }));

app.get("/", (_request, response) => response.sendFile(path.join(__dirname, "index.html")));
app.get("/login.html", (_request, response) => response.sendFile(path.join(__dirname, "login.html")));
app.get("/admin.html", (_request, response) => response.sendFile(path.join(__dirname, "admin.html")));
app.get("/styles.css", (_request, response) => response.sendFile(path.join(__dirname, "styles.css")));
app.get("/app.js", (_request, response) => response.sendFile(path.join(__dirname, "app.js")));
app.get("/login.js", (_request, response) => response.sendFile(path.join(__dirname, "login.js")));
app.get("/admin.js", (_request, response) => response.sendFile(path.join(__dirname, "admin.js")));
app.use("/assets", express.static(path.join(__dirname, "assets"), { dotfiles: "ignore" }));

const ensureColumn = async (tableName, columnName, columnDefinition) => {
  const [rows] = await pool.execute(
    `
      SELECT COLUMN_NAME
      FROM INFORMATION_SCHEMA.COLUMNS
      WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? AND COLUMN_NAME = ?
    `,
    [process.env.MYSQL_DATABASE, tableName, columnName]
  );

  if (!rows.length) {
    await pool.query(`ALTER TABLE ${tableName} ADD COLUMN ${columnName} ${columnDefinition}`);
  }
};

const initDatabase = async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(120) NOT NULL,
      email VARCHAR(190) NOT NULL UNIQUE,
      phone VARCHAR(40) NULL,
      gender VARCHAR(30) NULL,
      city VARCHAR(120) NULL,
      occupation VARCHAR(160) NULL,
      password_hash VARCHAR(255) NOT NULL,
      email_verified TINYINT(1) NOT NULL DEFAULT 0,
      verification_token_hash CHAR(64) NULL,
      verification_code_hash CHAR(64) NULL,
      verification_expires DATETIME NULL,
      last_login_at DATETIME NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS contact_messages (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      name VARCHAR(120) NOT NULL,
      email VARCHAR(190) NOT NULL,
      subject VARCHAR(120) NOT NULL,
      message TEXT NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      CONSTRAINT fk_contact_user
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  `);

  await ensureColumn("users", "last_login_at", "DATETIME NULL");
  await ensureColumn("users", "phone", "VARCHAR(40) NULL");
  await ensureColumn("users", "gender", "VARCHAR(30) NULL");
  await ensureColumn("users", "city", "VARCHAR(120) NULL");
  await ensureColumn("users", "occupation", "VARCHAR(160) NULL");
  await ensureColumn("users", "verification_code_hash", "CHAR(64) NULL");
};

const normalizeEmail = (email) => String(email || "").trim().toLowerCase();
const adminEmail = normalizeEmail(process.env.ADMIN_EMAIL || "shahrozali.f105@gmail.com");
const adminPassword = process.env.ADMIN_PASSWORD || "Shahroz.8027";
const isAdminUser = (user) => normalizeEmail(user.email) === adminEmail;
const hashToken = (token) => crypto.createHash("sha256").update(token).digest("hex");

const createJwt = (user, options = {}) => {
  return jwt.sign(
    { sub: user.id, email: user.email, isAdminSession: Boolean(options.isAdminSession) },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
};

const publicUser = (user, isAdminSession = false) => ({
  id: user.id,
  name: user.name,
  email: user.email,
  phone: user.phone || "",
  gender: user.gender || "",
  city: user.city || "",
  occupation: user.occupation || "",
  emailVerified: Boolean(user.email_verified),
  isAdmin: Boolean(isAdminSession) && isAdminUser(user)
});

const createVerificationChallenge = async (userId) => {
  const token = crypto.randomBytes(32).toString("hex");
  const code = String(crypto.randomInt(100000, 1000000));
  const tokenHash = hashToken(token);
  const codeHash = hashToken(code);

  await pool.execute(
    "UPDATE users SET verification_token_hash = ?, verification_code_hash = ?, verification_expires = DATE_ADD(UTC_TIMESTAMP(), INTERVAL 24 HOUR) WHERE id = ?",
    [tokenHash, codeHash, userId]
  );

  return { token, code };
};

const sendVerificationEmail = async (user, challenge) => {
  const token = typeof challenge === "string" ? challenge : challenge.token;
  const code = typeof challenge === "string" ? undefined : challenge.code;
  const verificationLink = `${appUrl}/?token=${encodeURIComponent(token)}#contact`;
  const showDevelopmentVerification = process.env.SHOW_VERIFICATION_LINK === "true";

  if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASS) {
    console.log(`Email verification link for ${user.email}: ${verificationLink}`);
    if (code) {
      console.log(`Email verification code for ${user.email}: ${code}`);
    }

    return {
      sent: false,
      needsEmailSetup: true,
      verificationLink: showDevelopmentVerification ? verificationLink : undefined,
      verificationCode: showDevelopmentVerification ? code : undefined
    };
  }

  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: process.env.SMTP_SECURE === "true",
    connectionTimeout: 15000,
    greetingTimeout: 15000,
    socketTimeout: 20000,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    }
  });

  try {
    await transporter.sendMail({
      from: process.env.MAIL_FROM || process.env.SMTP_USER,
      to: user.email,
      subject: "Verify your email for Shahroz portfolio",
      html: `
        <p>Hello ${escapeHtml(user.name)},</p>
        <p>Please verify your email address before sending a contact message.</p>
        ${code ? `<p>Your verification code is <strong>${code}</strong>.</p>` : ""}
        <p><a href="${verificationLink}">Verify email</a></p>
        <p>This link expires in 24 hours.</p>
      `
    });

    return { sent: true };
  } catch (error) {
    console.error("Verification email failed:", error.message);
    return {
      sent: false,
      needsEmailSetup: true,
      emailError: error.message
    };
  }
};

const pendingVerificationResponse = (response, user, emailResult, status = 202) => {
  response.status(status).json({
    pendingVerification: true,
    message: emailResult.sent
      ? "Account is pending email verification. Please check your email, verify it, then sign in."
      : "Account is pending email verification, but the verification email could not be sent. Please check SMTP settings.",
    email: user.email,
    needsEmailSetup: Boolean(emailResult.needsEmailSetup),
    emailError: emailResult.emailError,
    verificationLink: emailResult.verificationLink,
    verificationCode: emailResult.verificationCode
  });
};

const escapeHtml = (value) => {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
};

const authRequired = async (request, response, next) => {
  try {
    const authHeader = request.headers.authorization || "";
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";

    if (!token) {
      return response.status(401).json({ error: "Please sign in first." });
    }

    const payload = jwt.verify(token, process.env.JWT_SECRET);
    const [rows] = await pool.execute(
      "SELECT id, name, email, phone, gender, city, occupation, email_verified, last_login_at FROM users WHERE id = ?",
      [payload.sub]
    );

    if (!rows.length) {
      return response.status(401).json({ error: "Your account was not found." });
    }

    request.user = rows[0];
    request.isAdminSession = Boolean(payload.isAdminSession) && isAdminUser(rows[0]);
    next();
  } catch {
    response.status(401).json({ error: "Your session is invalid or expired." });
  }
};

const adminRequired = (request, response, next) => {
  if (!request.isAdminSession) {
    return response.status(403).json({ error: "Admin access is required." });
  }

  next();
};

app.post("/api/auth/signup", async (request, response) => {
  try {
    const name = String(request.body.name || "").trim();
    const email = normalizeEmail(request.body.email);
    const phone = String(request.body.phone || "").trim();
    const gender = String(request.body.gender || "").trim();
    const city = String(request.body.city || "").trim();
    const occupation = String(request.body.occupation || "").trim();
    const password = String(request.body.password || "");

    if (!name || !email || !phone || !password) {
      return response.status(400).json({ error: "Name, email, mobile number, and password are required." });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return response.status(400).json({ error: "Please enter a valid email address." });
    }

    if (!/^[0-9+\-\s()]{7,20}$/.test(phone)) {
      return response.status(400).json({ error: "Please enter a valid mobile number." });
    }

    if (password.length < 8) {
      return response.status(400).json({ error: "Password must be at least 8 characters." });
    }

    if (email === adminEmail && password !== adminPassword) {
      return response.status(403).json({ error: "This admin email must use the configured admin password." });
    }

    const [existingUsers] = await pool.execute(
      "SELECT id, name, email, email_verified FROM users WHERE email = ?",
      [email]
    );

    if (existingUsers.length) {
      const existingUser = existingUsers[0];

      if (existingUser.email_verified) {
        return response.status(409).json({ error: "An account with this email already exists. Please sign in." });
      }

      const challenge = await createVerificationChallenge(existingUser.id);
      const emailResult = await sendVerificationEmail(existingUser, challenge);
      return pendingVerificationResponse(response, existingUser, emailResult);
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const [result] = await pool.execute(
      "INSERT INTO users (name, email, phone, gender, city, occupation, password_hash) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [name, email, phone, gender || null, city || null, occupation || null, passwordHash]
    );

    const user = { id: result.insertId, name, email, phone, gender, city, occupation, email_verified: 0 };
    const challenge = await createVerificationChallenge(user.id);
    const emailResult = await sendVerificationEmail(user, challenge);

    return pendingVerificationResponse(response, user, emailResult, 201);
  } catch (error) {
    if (error.code === "ER_DUP_ENTRY") {
      return response.status(409).json({ error: "An account with this email already exists." });
    }

    console.error(error);
    response.status(500).json({ error: "Could not create account." });
  }
});

app.post("/api/auth/signin", async (request, response) => {
  const email = normalizeEmail(request.body.email);
  const password = String(request.body.password || "");
  const isAdminLogin = email === adminEmail;

  if (isAdminLogin && password !== adminPassword) {
    return response.status(401).json({ error: "Invalid admin email or password." });
  }

  const [rows] = await pool.execute(
    "SELECT id, name, email, phone, gender, city, occupation, password_hash, email_verified, last_login_at FROM users WHERE email = ?",
    [email]
  );

  const user = rows[0];

  if (!user) {
    if (isAdminLogin) {
      const passwordHash = await bcrypt.hash(adminPassword, 12);
      const [result] = await pool.execute(
        "INSERT INTO users (name, email, phone, gender, city, occupation, password_hash, email_verified, last_login_at) VALUES (?, ?, ?, ?, ?, ?, ?, 1, UTC_TIMESTAMP())",
        ["Shahroz", adminEmail, "", "Male", "", "Web developer", passwordHash]
      );
      const adminUser = {
        id: result.insertId,
        name: "Shahroz",
        email: adminEmail,
        phone: "",
        gender: "Male",
        city: "",
        occupation: "Web developer",
        email_verified: 1,
        last_login_at: new Date().toISOString()
      };

      return response.json({
        token: createJwt(adminUser, { isAdminSession: true }),
        user: publicUser(adminUser, true)
      });
    }

    return response.status(404).json({ error: "No account found with this email. Please register first." });
  }

  if (!isAdminLogin && !(await bcrypt.compare(password, user.password_hash))) {
    return response.status(401).json({ error: "Invalid email or password." });
  }

  if (!isAdminLogin && !user.email_verified) {
    const challenge = await createVerificationChallenge(user.id);
    const emailResult = await sendVerificationEmail(user, challenge);
    return response.status(403).json({
      error: emailResult.sent
        ? "Please verify your email before signing in. A new verification email has been sent."
        : "Please verify your email before signing in. The verification email could not be sent. Please check SMTP settings.",
      pendingVerification: true,
      email: user.email,
      needsEmailSetup: Boolean(emailResult.needsEmailSetup),
      emailError: emailResult.emailError,
      verificationLink: emailResult.verificationLink,
      verificationCode: emailResult.verificationCode
    });
  }

  if (isAdminLogin) {
    const passwordMatchesHash = await bcrypt.compare(adminPassword, user.password_hash);

    if (!passwordMatchesHash || !user.email_verified) {
      const passwordHash = await bcrypt.hash(adminPassword, 12);
      await pool.execute(
        "UPDATE users SET password_hash = ?, email_verified = 1 WHERE id = ?",
        [passwordHash, user.id]
      );
      user.email_verified = 1;
    }
  }

  const isAdminSession = isAdminLogin;

  await pool.execute("UPDATE users SET last_login_at = UTC_TIMESTAMP() WHERE id = ?", [user.id]);
  user.last_login_at = new Date().toISOString();

  response.json({
    token: createJwt(user, { isAdminSession }),
    user: publicUser(user, isAdminSession)
  });
});

app.get("/api/auth/me", authRequired, (request, response) => {
  if (!request.isAdminSession && !request.user.email_verified) {
    return response.status(403).json({
      error: "Please verify your email before signing in.",
      pendingVerification: true,
      email: request.user.email
    });
  }

  response.json({ user: publicUser(request.user, request.isAdminSession) });
});

app.get("/api/admin/summary", authRequired, adminRequired, async (_request, response) => {
  const [[userStats]] = await pool.query(`
    SELECT
      COUNT(*) AS totalUsers,
      SUM(CASE WHEN last_login_at IS NOT NULL THEN 1 ELSE 0 END) AS loggedInUsers,
      SUM(CASE WHEN email_verified = 1 THEN 1 ELSE 0 END) AS verifiedUsers
    FROM users
  `);

  const [[messageStats]] = await pool.query("SELECT COUNT(*) AS totalMessages FROM contact_messages");

  response.json({
    summary: {
      totalUsers: Number(userStats.totalUsers || 0),
      loggedInUsers: Number(userStats.loggedInUsers || 0),
      verifiedUsers: Number(userStats.verifiedUsers || 0),
      totalMessages: Number(messageStats.totalMessages || 0)
    }
  });
});

app.get("/api/admin/users", authRequired, adminRequired, async (_request, response) => {
  const [users] = await pool.query(`
    SELECT
      u.id,
      u.name,
      u.email,
      u.phone,
      u.gender,
      u.city,
      u.occupation,
      u.email_verified AS emailVerified,
      u.last_login_at AS lastLoginAt,
      u.created_at AS createdAt,
      COUNT(cm.id) AS messageCount
    FROM users u
    LEFT JOIN contact_messages cm ON cm.user_id = u.id
    GROUP BY u.id, u.name, u.email, u.phone, u.gender, u.city, u.occupation, u.email_verified, u.last_login_at, u.created_at
    ORDER BY u.last_login_at DESC, u.created_at DESC
  `);

  response.json({ users });
});

app.get("/api/admin/messages", authRequired, adminRequired, async (_request, response) => {
  const [messages] = await pool.query(`
    SELECT
      cm.id,
      cm.name,
      cm.email,
      cm.subject,
      cm.message,
      cm.created_at AS createdAt,
      u.name AS accountName,
      u.email AS accountEmail
    FROM contact_messages cm
    INNER JOIN users u ON u.id = cm.user_id
    ORDER BY cm.created_at DESC
  `);

  response.json({ messages });
});

app.get("/api/auth/verify-email", async (request, response) => {
  const token = String(request.query.token || "");

  if (!token) {
    return response.status(400).json({ error: "Verification token is required." });
  }

  const [rows] = await pool.execute(
    "SELECT id, name, email, email_verified FROM users WHERE verification_token_hash = ? AND verification_expires > UTC_TIMESTAMP()",
    [hashToken(token)]
  );

  if (!rows.length) {
    return response.status(400).json({ error: "Verification link is invalid or expired." });
  }

  await pool.execute(
    "UPDATE users SET email_verified = 1, verification_token_hash = NULL, verification_code_hash = NULL, verification_expires = NULL WHERE id = ?",
    [rows[0].id]
  );

  response.json({ message: "Email verified. You can now sign in." });
});

app.post("/api/auth/verify-code", async (request, response) => {
  const email = normalizeEmail(request.body.email);
  const code = String(request.body.code || "").trim();

  if (!email || !code) {
    return response.status(400).json({ error: "Email and verification code are required." });
  }

  if (!/^\d{6}$/.test(code)) {
    return response.status(400).json({ error: "Verification code must be 6 digits." });
  }

  const [rows] = await pool.execute(
    "SELECT id, email_verified FROM users WHERE email = ? AND verification_code_hash = ? AND verification_expires > UTC_TIMESTAMP()",
    [email, hashToken(code)]
  );

  if (!rows.length) {
    return response.status(400).json({ error: "Verification code is invalid or expired." });
  }

  await pool.execute(
    "UPDATE users SET email_verified = 1, verification_token_hash = NULL, verification_code_hash = NULL, verification_expires = NULL WHERE id = ?",
    [rows[0].id]
  );

  response.json({ message: "Email verified. You can now sign in." });
});

app.post("/api/auth/resend-verification-public", async (request, response) => {
  const email = normalizeEmail(request.body.email);

  if (!email) {
    return response.status(400).json({ error: "Email is required." });
  }

  const [rows] = await pool.execute(
    "SELECT id, name, email, email_verified FROM users WHERE email = ?",
    [email]
  );

  if (!rows.length) {
    return response.status(404).json({ error: "No account found with this email. Please register first." });
  }

  const user = rows[0];

  if (user.email_verified) {
    return response.json({ message: "Your email is already verified. Please sign in." });
  }

  const challenge = await createVerificationChallenge(user.id);
  const emailResult = await sendVerificationEmail(user, challenge);

  response.json({
    pendingVerification: true,
    message: emailResult.sent
      ? "Verification email sent. Please check your email, verify it, then sign in."
      : "The verification email could not be sent. Please check SMTP settings.",
    email: user.email,
    needsEmailSetup: Boolean(emailResult.needsEmailSetup),
    emailError: emailResult.emailError,
    verificationLink: emailResult.verificationLink,
    verificationCode: emailResult.verificationCode
  });
});

app.post("/api/auth/resend-verification", authRequired, async (request, response) => {
  if (request.user.email_verified) {
    return response.json({ message: "Your email is already verified." });
  }

  const challenge = await createVerificationChallenge(request.user.id);
  const emailResult = await sendVerificationEmail(request.user, challenge);

  response.json({
    message: emailResult.sent
      ? "Verification email sent."
      : "The verification email could not be sent. Please check SMTP settings.",
    needsEmailSetup: Boolean(emailResult.needsEmailSetup),
    emailError: emailResult.emailError,
    verificationLink: emailResult.verificationLink,
    verificationCode: emailResult.verificationCode
  });
});

app.post("/api/contact", authRequired, async (request, response) => {
  if (!request.user.email_verified) {
    return response.status(403).json({ error: "Please verify your email before sending a message." });
  }

  const name = request.user.name;
  const email = normalizeEmail(request.user.email);
  const subject = String(request.body.subject || "").trim();
  const message = String(request.body.message || "").trim();

  if (!subject || !message) {
    return response.status(400).json({ error: "Subject and message are required." });
  }

  await pool.execute(
    "INSERT INTO contact_messages (user_id, name, email, subject, message) VALUES (?, ?, ?, ?, ?)",
    [request.user.id, name, email, subject.slice(0, 120), message]
  );

  response.status(201).json({ message: "Your message was saved successfully." });
});

app.use((request, response) => {
  response.status(404).json({ error: `Route not found: ${request.method} ${request.path}` });
});

await initDatabase();

app.listen(port, () => {
  console.log(`Portfolio website running at ${appUrl}`);
});
