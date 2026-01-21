// app.js — AIForge (fixed, production-ready version for Render.com)
// January 2025 – inline EJS, no views folder needed

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const { OpenAI } = require('openai');
const validator = require('validator');
const ejs = require('ejs');

const app = express();
const PORT = process.env.PORT || 3000;

// ────────────────────────────────────────────────
//  Critical Environment Checks
// ────────────────────────────────────────────────
const requiredEnv = ['OPENAI_API_KEY', 'MONGODB_URI', 'SESSION_SECRET'];
for (const key of requiredEnv) {
  if (!process.env[key]) {
    console.error(`❌ Missing required env var: ${key}`);
    process.exit(1);
  }
}

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// ────────────────────────────────────────────────
//  Database
// ────────────────────────────────────────────────
mongoose.connect(process.env.MONGODB_URI, {
  serverSelectionTimeoutMS: 5000,
})
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => {
    console.error('❌ MongoDB connection failed:', err.message);
    process.exit(1);
  });

// ────────────────────────────────────────────────
//  User Model
// ────────────────────────────────────────────────
const userSchema = new mongoose.Schema({
  email:    { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  name:     { type: String, required: true },
  usage:    { type: Number, default: 0, min: 0 },
}, { timestamps: true });

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
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
//  Middleware
// ────────────────────────────────────────────────
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Session
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    collectionName: 'sessions',
    ttl: 7 * 24 * 60 * 60, // 1 week
  }),
  cookie: {
    maxAge: 7 * 24 * 60 * 60 * 1000,
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
  }
}));

// Make user available in templates + req
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
      console.error('Session user lookup failed:', err);
      req.session.destroy();
    }
  }
  next();
});

// ────────────────────────────────────────────────
//  Inline EJS Templates
// ────────────────────────────────────────────────
const templates = {
  layout: `<!DOCTYPE html>
<html lang="en" data-bs-theme="light">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AIForge • Business + Esports + Support</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
  <style>
    :root { --primary: #6c5ce7; --primary-dark: #5649c0; }
    body { background: linear-gradient(135deg, #f0f2ff 0%, #e6e9ff 100%); min-height: 100vh; font-family: system-ui, sans-serif; }
    .navbar-brand { font-weight: 800; color: var(--primary) !important; letter-spacing: -0.5px; }
    .card { border: none; border-radius: 1.1rem; box-shadow: 0 6px 24px rgba(0,0,0,0.08); overflow: hidden; }
    .usage-meter { height: 10px; background: #e9ecef; border-radius: 5px; overflow: hidden; }
    .usage-fill { height: 100%; background: linear-gradient(90deg, #00d084, #00f2c3); transition: width 0.6s ease; }
    .btn-primary { background: var(--primary); border-color: var(--primary); }
    .btn-primary:hover { background: var(--primary-dark); border-color: var(--primary-dark); }
    pre { white-space: pre-wrap; word-break: break-word; background: #1e1e2e !important; color: #c5c8ff; }
  </style>
</head>
<body>
  <nav class="navbar navbar-expand-lg navbar-light bg-white shadow-sm">
    <div class="container">
      <a class="navbar-brand" href="/"><i class="fas fa-crown me-2"></i>AIForge</a>
      <div class="ms-auto d-flex align-items-center gap-3">
        <% if (user) { %>
          <div class="d-flex align-items-center gap-2">
            <span><strong><%= user.name %></strong></span>
            <% if (isAdmin) { %>
              <span class="badge bg-gradient text-white px-3 py-2" style="background: linear-gradient(90deg, #6c5ce7, #a29bfe);">ADMIN</span>
            <% } %>
          </div>
          <form action="/logout" method="POST" class="m-0">
            <button type="submit" class="btn btn-outline-secondary btn-sm px-3">Logout</button>
          </form>
        <% } else { %>
          <a href="/login" class="btn btn-primary btn-sm px-4">Login</a>
        <% } %>
      </div>
    </div>
  </nav>

  <main class="flex-grow-1">
    <%- body %>
  </main>

  <footer class="bg-dark text-white text-center py-4 mt-5">
    <small>© 2025–2026 AIForge • Free $5 credit for theceoion@gmail.com only</small>
  </footer>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz" crossorigin="anonymous"></script>
</body>
</html>`,

  index: `<% const FREE_CREDIT = 5.00; %>
<div class="container py-5">
  <div class="text-center mb-5">
    <h1 class="display-4 fw-bold">AIForge</h1>
    <p class="lead text-muted">Code • Data • Analysis • Stories • Emotional Support</p>
  </div>

  <% if (!user) { %>
    <div class="alert alert-info text-center shadow-sm">
      Please <a href="/login" class="alert-link">log in</a> to access the AI.
    </div>
  <% } else { %>
    <div class="row justify-content-center">
      <div class="col-lg-8 col-xl-7">
        <div class="card p-4 p-md-5">
          <div class="d-flex justify-content-between align-items-center mb-4">
            <h4 class="mb-0">AI Dashboard</h4>
            <% if (isAdmin) { %>
              <span class="badge bg-success px-3 py-2 fs-6">$<%= FREE_CREDIT %> free credit</span>
            <% } else { %>
              <span class="badge bg-warning text-dark px-3 py-2 fs-6">Paid plan required</span>
            <% } %>
          </div>

          <p class="mb-2">Total spent: <strong>$<%= usage.toFixed(4) %></strong></p>

          <% if (isAdmin) { %>
            <div class="usage-meter mb-2">
              <div class="usage-fill" style="width: <%= Math.min(100, (usage / FREE_CREDIT) * 100) %>%"></div>
            </div>
            <small class="text-muted">Remaining: $<%= (FREE_CREDIT - usage).toFixed(4) %></small>
          <% } %>

          <% if ((isAdmin && usage >= FREE_CREDIT) || (!isAdmin && usage > 0)) { %>
            <div class="alert alert-warning mt-4">
              <i class="fas fa-exclamation-triangle me-2"></i>
              <%= isAdmin ? 'Free admin credit exhausted ($5)' : 'Non-admin accounts require payment' %>
            </div>
          <% } %>

          <form id="aiForm" class="mt-4">
            <div class="mb-4">
              <label class="form-label fw-bold">AI Mode</label>
              <div class="d-flex flex-wrap gap-2">
                <button type="button" class="btn btn-outline-primary mode-btn active" data-mode="general">General</button>
                <button type="button" class="btn btn-outline-success mode-btn" data-mode="code">Code</button>
                <button type="button" class="btn btn-outline-info mode-btn" data-mode="data">Data</button>
                <button type="button" class="btn btn-outline-warning mode-btn" data-mode="therapist">Therapist</button>
                <button type="button" class="btn btn-outline-secondary mode-btn" data-mode="custom">Custom</button>
              </div>
              <input type="hidden" id="mode" name="mode" value="general">
            </div>

            <div class="mb-4">
              <textarea class="form-control" name="prompt" rows="5" placeholder="Your request..." required></textarea>
            </div>

            <button type="submit" class="btn btn-primary btn-lg w-100" id="submitBtn"
              <%= (isAdmin && usage >= FREE_CREDIT) || (!isAdmin && usage > 0) ? 'disabled' : '' %>>
              <i class="fas fa-rocket me-2"></i> Generate
            </button>
          </form>

          <pre id="result" class="mt-4 p-4 rounded bg-dark text-light" style="display:none; min-height:120px;"></pre>
        </div>
      </div>
    </div>
  <% } %>
</div>

<script>
document.querySelectorAll('.mode-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.mode-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('mode').value = btn.dataset.mode;
  });
});

document.getElementById('aiForm')?.addEventListener('submit', async e => {
  e.preventDefault();
  const form = e.target;
  const btn = document.getElementById('submitBtn');
  const result = document.getElementById('result');

  const originalText = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span> Generating...';

  try {
    const res = await fetch('/api/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        prompt: form.prompt.value.trim(),
        mode: document.getElementById('mode').value
      })
    });

    const data = await res.json();

    if (!res.ok) throw new Error(data.error || 'Generation failed');

    result.textContent = data.content;
    result.style.display = 'block';
    window.scrollTo({ top: document.body.scrollHeight, behavior: 'smooth' });

    // Optional: refresh usage
    setTimeout(() => location.reload(), 1800);

  } catch (err) {
    result.textContent = 'Error: ' + err.message;
    result.style.display = 'block';
  } finally {
    btn.disabled = false;
    btn.innerHTML = originalText;
  }
});
</script>`,

  login: `<div class="container">
  <div class="row justify-content-center min-vh-100 align-items-center">
    <div class="col-md-6 col-lg-5 col-xl-4">
      <div class="card shadow-lg p-4 p-md-5">
        <h3 class="text-center mb-4 fw-bold">AIForge Login</h3>

        <% if (error) { %>
          <div class="alert alert-danger"><%= error %></div>
        <% } %>

        <form method="POST">
          <div class="mb-3">
            <input type="email" name="email" class="form-control form-control-lg" placeholder="Email" required autofocus>
          </div>
          <div class="mb-4">
            <input type="password" name="password" class="form-control form-control-lg" placeholder="Password" required>
          </div>
          <button type="submit" class="btn btn-primary btn-lg w-100">Sign In</button>
        </form>

        <div class="text-center mt-4 text-muted small">
          Admin free tier ($5) → only theceoion@gmail.com
        </div>
      </div>
    </div>
  </div>
</div>`
};

// Custom EJS engine for inline templates (this fixes your original error)
app.engine('ejs', async (filePath, options, callback) => {
  try {
    const name = filePath.split(/[\\/]/).pop().replace(/\.ejs$/i, '');
    if (!templates[name]) {
      return callback(new Error(`Inline template "${name}" not found`));
    }

    const body = await ejs.render(templates[name], options, { async: true });
    const html = await ejs.render(templates.layout, { ...options, body }, { async: true });

    callback(null, html);
  } catch (err) {
    callback(err);
  }
});

app.set('view engine', 'ejs');
app.set('views', '.');   // required even with custom engine

// ────────────────────────────────────────────────
//  Helpers
// ────────────────────────────────────────────────
function requireLogin(req, res, next) {
  if (!req.session?.userId) return res.redirect('/login');
  next();
}

const calculateCost = (promptTokens, completionTokens) => {
  // gpt-4o pricing — update if model changes
  const input  = promptTokens   / 1_000_000 * 2.50;
  const output = completionTokens / 1_000_000 * 10.00;
  return Number((input + output).toFixed(4));
};

const sanitize = str => validator.escape((str || '').trim()).substring(0, 4000);

const THERAPIST_SYSTEM = `
You are a warm, ethical, non-judgmental AI companion — NOT a licensed therapist.
Rules you MUST follow:
1. Never give medical, psychiatric or therapeutic advice
2. Never diagnose or suggest medication
3. If user mentions self-harm/suicide: respond with empathy + strongly urge 988 (US) or local crisis line
4. Redirect serious concerns to professionals
5. Stay supportive, reflective, validating
`;

// ────────────────────────────────────────────────
//  Routes
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
      return res.render('login', { error: 'Invalid email or password' });
    }

    req.session.userId = user._id.toString();
    res.redirect('/');
  } catch (err) {
    console.error(err);
    res.render('login', { error: 'Something went wrong. Try again.' });
  }
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

app.post('/api/generate', requireLogin, async (req, res) => {
  const { prompt, mode } = req.body;
  const FREE_LIMIT = 5.00;

  if (!prompt?.trim()) return res.status(400).json({ error: 'Prompt required' });

  const { isAdmin, usage } = req.user;

  if (!isAdmin && usage > 0) {
    return res.status(402).json({ error: 'Non-admin accounts require payment' });
  }
  if (isAdmin && usage >= FREE_LIMIT) {
    return res.status(402).json({ error: 'Admin $5 free credit used up' });
  }

  let system = "You are a highly capable, precise AI assistant.";
  if (mode === 'therapist') system = THERAPIST_SYSTEM;
  if (mode === 'code')      system = "You are a senior software engineer. Write clean, secure, well-commented code.";
  if (mode === 'data')      system = "You are a data scientist. Generate realistic synthetic datasets in clean JSON.";

  try {
    const completion = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [
        { role: "system", content: system },
        { role: "user",   content: sanitize(prompt) }
      ],
      temperature: mode === 'therapist' ? 0.85 : 0.7,
      max_tokens: 1600
    });

    const choice = completion.choices[0];
    const cost = calculateCost(
      completion.usage.prompt_tokens,
      completion.usage.completion_tokens
    );

    const newUsage = Number((usage + cost).toFixed(4));
    await User.findByIdAndUpdate(req.user._id, { $set: { usage: newUsage } });

    res.json({
      success: true,
      content: choice.message.content,
      cost,
      newUsage
    });

  } catch (err) {
    console.error('OpenAI error:', err);
    const msg = err?.code === 'insufficient_quota' ? 'OpenAI quota exceeded' : 'AI generation failed';
    res.status(500).json({ error: msg });
  }
});

// ────────────────────────────────────────────────
//  Admin Bootstrap + Server Start
// ────────────────────────────────────────────────
const server = app.listen(PORT, async () => {
  console.log(`🚀 AIForge running → http://localhost:${PORT}`);

  // Create admin if missing
  try {
    const adminEmail = 'theceoion@gmail.com';
    if (!await User.exists({ email: adminEmail })) {
      await new User({
        email: adminEmail,
        password: 'ChangeMeSecure123!!', // ← CHANGE THIS or use one-time setup script
        name: 'Admin'
      }).save();
      console.log(`Admin account created: ${adminEmail}`);
    }
  } catch (err) {
    console.error('Admin bootstrap failed:', err.message);
  }
});

// Graceful shutdown (important on Render)
process.on('SIGTERM', () => {
  console.log('SIGTERM received → shutting down');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});
