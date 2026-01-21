// app.js
// AIForge – using real views/ folder (index.ejs, login.ejs, layout.ejs)
// No custom engine needed – standard EJS setup

require('dotenv').config();
const express = require('express');
const path = require('path');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const { OpenAI } = require('openai');
const validator = require('validator');

const app = express();
const PORT = process.env.PORT || 3000;

// ────────────────────────────────────────────────
// Environment validation
// ────────────────────────────────────────────────
const required = ['OPENAI_API_KEY', 'MONGODB_URI', 'SESSION_SECRET'];
for (const key of required) {
  if (!process.env[key]) {
    console.error(`Missing required env var: ${key}`);
    process.exit(1);
  }
}

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// ────────────────────────────────────────────────
// MongoDB connection
// ────────────────────────────────────────────────
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => {
    console.error('❌ MongoDB failed:', err.message);
    process.exit(1);
  });

// ────────────────────────────────────────────────
// User Model
// ────────────────────────────────────────────────
const userSchema = new mongoose.Schema({
  email:    { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  name:     { type: String, required: true },
  usage:    { type: Number, default: 0, min: 0 },
}, { timestamps: true });

userSchema.pre('save', async function(next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 12);
  }
  next();
});

userSchema.methods.comparePassword = async function(candidate) {
  return bcrypt.compare(candidate, this.password);
};

userSchema.virtual('isAdmin').get(function() {
  return this.email === 'theceoion@gmail.com';
});

const User = mongoose.model('User', userSchema);

// ────────────────────────────────────────────────
// Middleware
// ────────────────────────────────────────────────
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Session store in MongoDB
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    collectionName: 'sessions',
    ttl: 7 * 24 * 60 * 60
  }),
  cookie: {
    maxAge: 7 * 24 * 60 * 60 * 1000,
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax'
  }
}));

// Make user data available in templates & req
app.use(async (req, res, next) => {
  res.locals.user = null;
  res.locals.isAdmin = false;
  res.locals.usage = 0;

  if (req.session.userId) {
    try {
      const user = await User.findById(req.session.userId).lean();
      if (user) {
        req.user = user;
        res.locals.user = user;
        res.locals.isAdmin = user.isAdmin;
        res.locals.usage = user.usage;
      } else {
        req.session.destroy();
      }
    } catch (err) {
      console.error('Session user error:', err.message);
      req.session.destroy();
    }
  }
  next();
});

// ────────────────────────────────────────────────
// EJS + Views Setup (this is the key part)
// ────────────────────────────────────────────────
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));  // ← points to your views/ folder

// ────────────────────────────────────────────────
// Helper functions
// ────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (!req.session?.userId) return res.redirect('/login');
  next();
}

function calculateCost(promptTokens, completionTokens) {
  const input  = (promptTokens   / 1_000_000) * 2.50;
  const output = (completionTokens / 1_000_000) * 10.00;
  return Number((input + output).toFixed(4));
}

function sanitize(str) {
  return validator.escape((str || '').trim()).substring(0, 4000);
}

const THERAPIST_SYSTEM = `
You are a supportive, ethical AI companion — NOT a licensed therapist.
Rules: Never give medical advice, never diagnose, redirect serious concerns to professionals (e.g. 988 in US).
Be empathetic, validating, reflective.
`;

// ────────────────────────────────────────────────
// Routes
// ────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.render('index', {
    user: res.locals.user,
    isAdmin: res.locals.isAdmin,
    usage: res.locals.usage || 0
  });
});

app.get('/login', (req, res) => {
  if (req.session.userId) return res.redirect('/');
  res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.render('login', { error: 'Email and password required' });
  }

  try {
    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user || !(await user.comparePassword(password))) {
      return res.render('login', { error: 'Invalid credentials' });
    }
    req.session.userId = user._id.toString();
    res.redirect('/');
  } catch (err) {
    console.error(err);
    res.render('login', { error: 'Server error – try again' });
  }
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

app.post('/api/generate', requireAuth, async (req, res) => {
  const { prompt, mode } = req.body;
  const FREE_LIMIT = 5.00;

  if (!prompt?.trim()) return res.status(400).json({ error: 'Prompt required' });

  const { isAdmin, usage } = req.user;

  if (!isAdmin && usage > 0) {
    return res.status(402).json({ error: 'Payment required for non-admin' });
  }
  if (isAdmin && usage >= FREE_LIMIT) {
    return res.status(402).json({ error: 'Admin free credit exhausted' });
  }

  let system = "You are a helpful, professional AI assistant.";
  if (mode === 'therapist') system = THERAPIST_SYSTEM;
  if (mode === 'code') system = "You are a senior developer. Write clean, secure code.";
  if (mode === 'data') system = "Generate realistic synthetic data in JSON.";

  try {
    const completion = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [
        { role: "system", content: system },
        { role: "user", content: sanitize(prompt) }
      ],
      temperature: mode === 'therapist' ? 0.85 : 0.7,
      max_tokens: 1600
    });

    const cost = calculateCost(
      completion.usage.prompt_tokens,
      completion.usage.completion_tokens
    );

    const newUsage = Number((usage + cost).toFixed(4));
    await User.findByIdAndUpdate(req.user._id, { usage: newUsage });

    res.json({
      success: true,
      content: completion.choices[0].message.content,
      cost,
      newUsage
    });
  } catch (err) {
    console.error('OpenAI error:', err.message);
    res.status(500).json({ error: 'Generation failed' });
  }
});

// ────────────────────────────────────────────────
// Start server + admin bootstrap
// ────────────────────────────────────────────────
const server = app.listen(PORT, async () => {
  console.log(`🚀 Server running on port ${PORT}`);

  // Create admin if missing
  try {
    const adminEmail = 'theceoion@gmail.com';
    if (!await User.exists({ email: adminEmail })) {
      await new User({
        email: adminEmail,
        password: 'ChangeMe123Secure!', // ← CHANGE THIS!
        name: 'Admin'
      }).save();
      console.log('Admin account created');
    }
  } catch (err) {
    console.error('Admin setup failed:', err.message);
  }
});

process.on('SIGTERM', () => {
  server.close(() => {
    console.log('Server shut down');
    process.exit(0);
  });
});
