// app.js
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

// ─── Environment check ────────────────────────────────────────
if (!process.env.OPENAI_API_KEY || !process.env.MONGODB_URI || !process.env.SESSION_SECRET) {
  console.error('Missing critical environment variables');
  process.exit(1);
}

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// ─── MongoDB ──────────────────────────────────────────────────
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => {
    console.error('MongoDB connection failed:', err.message);
    process.exit(1);
  });

// ─── User Model ───────────────────────────────────────────────
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  name: { type: String, required: true },
  usage: { type: Number, default: 0 }
});

userSchema.pre('save', async function(next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 12);
  }
  next();
});

userSchema.methods.comparePassword = async function(candidate) {
  return bcrypt.compare(candidate, this.password);
};

const User = mongoose.model('User', userSchema);

// ─── Middleware ───────────────────────────────────────────────
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Session
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: process.env.MONGODB_URI }),
  cookie: {
    maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax'
  }
}));

// User to locals
app.use(async (req, res, next) => {
  res.locals.user = null;
  if (req.session.userId) {
    try {
      const user = await User.findById(req.session.userId).lean();
      if (user) res.locals.user = user;
      else req.session.destroy();
    } catch (err) {
      req.session.destroy();
    }
  }
  next();
});

// Views setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ─── Routes ───────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.render('index', { user: res.locals.user });
});

app.get('/login', (req, res) => {
  if (res.locals.user) return res.redirect('/');
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

    req.session.userId = user._id;
    res.redirect('/');
  } catch (err) {
    console.error(err);
    res.render('login', { error: 'Server error – try again later' });
  }
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

app.post('/api/chat', async (req, res) => {
  if (!res.locals.user) {
    return res.status(401).json({ error: 'Not logged in' });
  }

  const { message } = req.body;
  if (!message || typeof message !== 'string' || message.trim().length === 0) {
    return res.status(400).json({ error: 'Message required' });
  }

  const cleanMessage = validator.escape(message.trim()).substring(0, 3000);

  try {
    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",           // cheaper & faster than gpt-4o
      messages: [
        { role: "system", content: "You are a helpful, concise assistant." },
        { role: "user", content: cleanMessage }
      ],
      temperature: 0.7,
      max_tokens: 1200
    });

    const reply = completion.choices[0].message.content.trim();

    // Optional: update usage (tokens-based example)
    const tokensUsed = completion.usage?.total_tokens || 0;
    await User.findByIdAndUpdate(res.locals.user._id, {
      $inc: { usage: tokensUsed / 1000 }  // rough cost proxy
    });

    res.json({ reply });
  } catch (err) {
    console.error('OpenAI error:', err.message);
    res.status(500).json({ error: 'AI service unavailable right now' });
  }
});

// Create default admin user (runs on startup)
(async () => {
  try {
    const adminEmail = 'admin@example.com'; // ← CHANGE THIS
    if (!await User.exists({ email: adminEmail })) {
      const admin = new User({
        email: adminEmail,
        password: 'CUNT',         // ← CHANGE THIS
        name: 'Admin'
      });
      await admin.save();
      console.log('Default admin created');
    }
  } catch (err) {
    console.error('Admin creation failed:', err.message);
  }
})();

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
