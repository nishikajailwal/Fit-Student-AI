import express from "express";
import { createServer as createViteServer } from "vite";
import cors from "cors";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import Database from "better-sqlite3";
import path from "path";
import dotenv from "dotenv";

dotenv.config();

const db = new Database("fitness.db");

// Initialize Database
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT,
    name TEXT,
    age INTEGER,
    gender TEXT,
    height REAL,
    weight REAL,
    goal TEXT,
    budget TEXT,
    diet_pref TEXT,
    location TEXT,
    experience TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS progress (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    weight REAL,
    date TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS plans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    type TEXT, -- 'workout' or 'diet'
    content TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );
`);

async function startServer() {
  const app = express();
  const PORT = 3000;
  const JWT_SECRET = process.env.JWT_SECRET || "student-fitness-secret";

  app.use(cors());
  app.use(express.json());

  // Health Check
  app.get("/api/health", (req, res) => {
    res.json({ status: "ok", timestamp: new Date().toISOString() });
  });

  // Auth Middleware
  const authenticate = (req: any, res: any, next: any) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ error: "Unauthorized" });
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      req.user = decoded;
      next();
    } catch (e) {
      res.status(401).json({ error: "Invalid token" });
    }
  };

  // Auth Routes
  app.post("/api/auth/register", async (req, res) => {
    const { email, password, name } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 10);
    try {
      const info = db.prepare("INSERT INTO users (email, password, name) VALUES (?, ?, ?)").run(email, hashedPassword, name);
      const token = jwt.sign({ id: info.lastInsertRowid, email }, JWT_SECRET);
      res.json({ token, user: { id: info.lastInsertRowid, email, name } });
    } catch (e) {
      res.status(400).json({ error: "Email already exists" });
    }
  });

  app.post("/api/auth/login", async (req, res) => {
    const { email, password } = req.body;
    const user: any = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
    if (user && bcrypt.compareSync(password, user.password)) {
      const token = jwt.sign({ id: user.id, email }, JWT_SECRET);
      res.json({ token, user: { id: user.id, email, name: user.name } });
    } else {
      res.status(401).json({ error: "Invalid credentials" });
    }
  });

  // User Profile
  app.get("/api/user/profile", authenticate, (req: any, res) => {
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.id);
    res.json(user);
  });

  app.post("/api/user/profile", authenticate, (req: any, res) => {
    try {
      const { age, gender, height, weight, goal, budget, diet_pref, location, experience } = req.body;
      
      const result = db.prepare(`
        UPDATE users SET 
          age = ?, gender = ?, height = ?, weight = ?, goal = ?, 
          budget = ?, diet_pref = ?, location = ?, experience = ?
        WHERE id = ?
      `).run(
        age ?? null, 
        gender ?? null, 
        height ?? null, 
        weight ?? null, 
        goal ?? null, 
        budget ?? null, 
        diet_pref ?? null, 
        location ?? null, 
        experience ?? null, 
        req.user.id
      );

      if (result.changes === 0) {
        return res.status(404).json({ error: "User not found" });
      }
      
      // Log weight in progress if provided
      if (weight) {
        db.prepare("INSERT INTO progress (user_id, weight, date) VALUES (?, ?, ?)").run(
          req.user.id, 
          weight, 
          new Date().toISOString().split('T')[0]
        );
      }
      
      res.json({ success: true });
    } catch (e: any) {
      console.error("Profile update error:", e);
      res.status(500).json({ error: e.message });
    }
  });

  // Progress Tracking
  app.get("/api/user/progress", authenticate, (req: any, res) => {
    const progress = db.prepare("SELECT * FROM progress WHERE user_id = ? ORDER BY date ASC").all(req.user.id);
    res.json(progress);
  });

  app.post("/api/user/progress", authenticate, (req: any, res) => {
    const { weight, date } = req.body;
    db.prepare("INSERT INTO progress (user_id, weight, date) VALUES (?, ?, ?)").run(req.user.id, weight, date || new Date().toISOString().split('T')[0]);
    res.json({ success: true });
  });

  // Save generated plan
  app.post("/api/plans/save", authenticate, (req: any, res) => {
    const { type, content } = req.body;
    db.prepare("INSERT INTO plans (user_id, type, content) VALUES (?, ?, ?)").run(req.user.id, type, content);
    res.json({ success: true });
  });

  app.get("/api/plans", authenticate, (req: any, res) => {
    const plans = db.prepare("SELECT * FROM plans WHERE user_id = ? ORDER BY created_at DESC").all(req.user.id);
    res.json(plans);
  });

  // AI Chat Assistant (Placeholder - now handled on frontend)
  app.post("/api/chat/config", authenticate, (req: any, res) => {
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.id);
    res.json(user);
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.resolve(__dirname, "dist")));
    app.get("*", (req, res) => {
      res.sendFile(path.resolve(__dirname, "dist", "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
