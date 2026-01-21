// app.js — 100% filesystem-free, inline templates, .env admin, OpenAI
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const { OpenAI } = require('openai');
const validator = require('validator');

const app = express();
const PORT = process.env.PORT || 3000;

// Validate env
const requiredEnv = ['OPENAI_API_KEY', 'MONGODB_URI', 'USER', 'PASSWORD'];
for (const key of requiredEnv) {
  if (!process.env[key]) {
    console.error(`❌ Missing ${key}`);
    process.exit(1);
  }
}

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// DB
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => {
    console.error('❌ DB Error:', err);
    process.exit(1);
  });

// User model
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  name: { type: String, required: true },
  usage: { type: Number, default: 0 }
});

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

userSchema.methods.comparePassword = async function(candidate) {
  return await bcrypt.compare(candidate, this.password);
};

userSchema.virtual('isAdmin').get(function() {
  return this.email === process.env.USER;
});

userSchema.set('toJSON', { virtuals: true });
const User = mongoose.model('User', userSchema);

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const sessionMiddleware = session({
  secret: process.env.SESSION_SECRET || 'dev-secret',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: process.env.MONGODB_URI }),
  cookie: { 
    maxAge: 7 * 24 * 60 * 60 * 1000,
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production'
  }
});

app.use((req, res, next) => {
  sessionMiddleware(req, res, (err) => {
    if (err) {
      console.error('Session error:', err);
      return res.status(500).send('Session error');
    }
    next();
  });
});

// ✅ INLINE TEMPLATES — NO EJS ENGINE, NO FILESYSTEM
const renderTemplate = (templateName, options = {}) => {
  const ejs = require('ejs');
  
  const templates = {
    layout: `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>AIForge | Admin AI Platform</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"/>
  <style>
    :root { --primary: #6c5ce7; }
    body { background: linear-gradient(135deg, #f8f9ff, #eef2ff); min-height: 100vh; }
    .navbar-brand { font-weight: 700; color: var(--primary) !important; }
    .card { border-radius: 16px; box-shadow: 0 4px 20px rgba(0,0,0,0.06); }
    .usage-meter { height: 12px; background: #e9ecef; border-radius: 6px; margin: 10px 0; overflow: hidden; }
    .usage-fill { height: 100%; border-radius: 6px; }
    .badge-admin { background: linear-gradient(135deg, #6c5ce7, #a29bfe); }
    .mode-btn { transition: all 0.2s; }
    .mode-btn.active { background: var(--primary); color: white; }
  </style>
</head>
<body>
  <nav class="navbar navbar-light bg-white shadow-sm">
    <div class="container d-flex justify-content-between">
      <a class="navbar-brand" href="/"><i class="fas fa-crown me-2"></i>AIForge</a>
      <div>
        <% if (locals.user) { %>
          <span><b><%= user.name %></b> 
            <% if (isAdmin) { %>
              <span class="badge badge-admin text-white">ADMIN</span>
            <% } %>
          </span>
          <form action="/logout" method="POST" class="d-inline ms-2">
            <button type="submit" class="btn btn-outline-secondary btn-sm">Logout</button>
          </form>
        <% } else { %>
          <a href="/login" class="btn btn-primary btn-sm">Login</a>
        <% } %>
      </div>
    </div>
  </nav>
  <%- body %>
  <footer class="bg-dark text-light py-3 mt-5">
    <div class="container text-center">
      <small>© 2026 AIForge • Admin: <%= process.env.USER || 'admin' %></small>
    </div>
  </footer>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
    `,
    
    index: `
<% const FREE_LIMIT = 5; %>
<div class="container py-5">
  <div class="text-center mb-5">
    <h1 class="display-5 fw-bold">AIForge: Business, Esports & Support</h1>
    <p class="lead">Professional AI for code, data, analysis, stories, and emotional support</p>
  </div>

  <% if (!user) { %>
    <div class="alert alert-info text-center">Please <a href="/login">log in</a> to access AI features</div>
  <% } else { %>
    <div class="row justify-content-center">
      <div class="col-md-8">
        <div class="card p-4">
          <div class="d-flex justify-content-between align-items-center mb-3">
            <h5>UsageIdashboard</h5>
            <% if (isAdmin) { %>
              <span class="badge bg-success">Free Tier: $5</span>
            <% } else { %>
              <span class="badge bg-danger">Paid Plan Required</span>
            <% } %>
          </div>

          <p>Total used: <b>$<%= usage.toFixed(4) %></b></p>

          <% if (isAdmin) { %>
            <div class="usage-meter">
              <div class="usage-fill bg-success" style="width: <%= Math.min(100, (usage / FREE_LIMIT) * 100) %>%"></div>
            </div>
            <small class="text-muted">Remaining: $<%= (FREE_LIMIT - usage).toFixed(4) %></small>
          <% } %>

          <% if ((isAdmin && usage >= FREE_LIMIT) || (!isAdmin && usage > 0)) { %>
            <div class="alert alert-warning mt-3">
              <i class="fas fa-exclamation-triangle me-2"></i>
              <%= isAdmin ? 'Admin free tier exhausted' : 'Payment required for non-admin accounts' %>
            </div>
          <% } %>

          <div class="mb-3">
            <label class="form-label">AI Mode</label>
            <div class="d-flex flex-wrap gap-2">
              <button type="button" class="btn btn-outline-primary mode-btn active" data-mode="general">General</button>
              <button type="button" class="btn btn-outline-success mode-btn" data-mode="code">Code</button>
              <button type="button" class="btn btn-outline-info mode-btn" data-mode="data">Data</button>
              <button type="button" class="btn btn-outline-warning mode-btn" data-mode="therapist">Therapist</button>
              <button type="button" class="btn btn-outline-secondary mode-btn" data-mode="custom">Custom</button>
            </div>
            <input type="hidden" id="modeInput" name="mode" value="general">
          </div>

          <form id="aiForm" class="mt-3">
            <div class="mb-3">
              <textarea class="form-control" name="prompt" rows="4" placeholder="Describe your request..." required></textarea>
            </div>
            <button type="submit" class="btn btn-primary w-100"
              <%= ((isAdmin && usage >= FREE_LIMIT) || (!isAdmin && usage > 0)) ? 'disabled' : '' %>>
              <i class="fas fa-bolt me-2"></i> Generate with AI
            </button>
          </form>

          <pre id="result" class="mt-4 bg-light p-3 rounded" style="display:none; white-space: pre-wrap;"></pre>
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
    document.getElementById('modeInput').value = btn.dataset.mode;
  });
});

document.getElementById('aiForm')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const mode = document.getElementById('modeInput').value;
  const prompt = e.target.prompt.value;
  
  const btn = e.submitter;
  const original = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span> Processing...';

  try {
    const res = await fetch('/api/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ prompt, mode })
    });
    const data = await res.json();
    
    if (res.ok) {
      document.getElementById('result').textContent = data.content;
      document.getElementById('result').style.display = 'block';
      setTimeout(() => location.reload(), 2000);
    } else {
      alert('Error: ' + (data.error || 'Unknown'));
    }
  } catch (err) {
    alert('Network error: ' + err.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = original;
  }
});
</script>
    `,
    
    login: `
<div class="container d-flex align-items-center justify-content-center min-vh-100">
  <div class="col-md-6 col-lg-4">
    <div class="card p-4 shadow">
      <h3 class="text-center mb-4">AIForge Login</h3>
      <% if (locals.error) { %>
        <div class="alert alert-danger"><%= error %></div>
      <% } %>
      <form method="POST">
        <div class="mb-3">
          <input type="email" class="form-control" name="email" placeholder="Email" required>
        </div>
        <div class="mb-3">
          <input type="password" class="form-control" name="password" placeholder="Password" required>
        </div>
        <button type="submit" class="btn btn-primary w-100">Login</button>
      </form>
      <div class="text-center mt-3">
        <small class="text-muted">Admin: <%= process.env.USER || 'admin@example.com' %></small>
      </div>
    </div>
  </div>
</div>
    `
  };

  if (!templates[templateName]) {
    throw new Error(`Template not found: ${templateName}`);
  }

  const body = ejs.render(templates[templateName], { ...options, locals: options });
  return ejs.render(templates.layout, { ...options, body, locals: options });
};

// Auth helper
async function getUserFromSession(req) {
  if (!req.session || !req.session.userId) return null;
  try {
    return await User.findById(req.session.userId).lean();
  } catch (err) {
    req.session.destroy();
    return null;
  }
}

// Routes using res.send() instead of res.render()
app.get('/', async (req, res) => {
  const user = await getUserFromSession(req);
  const usage = user ? user.usage : 0;
  const isAdmin = user ? user.isAdmin : false;
  
  try {
    const html = renderTemplate('index', { user, usage, isAdmin });
    res.send(html);
  } catch (err) {
    console.error('Template error:', err);
    res.status(500).send('Template error');
  }
});

app.get('/login', (req, res) => {
  try {
    const html = renderTemplate('login', { error: null });
    res.send(html);
  } catch (err) {
    res.status(500).send('Template error');
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email: email?.toLowerCase().trim() });
    if (!user || !(await user.comparePassword(password))) {
      const html = renderTemplate('login', { error: 'Invalid credentials' });
      return res.send(html);
    }
    req.session.userId = user._id.toString();
    res.redirect('/');
  } catch (err) {
    const html = renderTemplate('login', { error: 'Server error' });
    res.send(html);
  }
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

// AI endpoint
const calculateCost = (promptTokens, completionTokens) => {
  const inputCost = (promptTokens / 1_000_000) * 2.50;
  const outputCost = (completionTokens / 1_000_000) * 10.00;
  return parseFloat((inputCost + outputCost).toFixed(4));
};

const sanitizeInput = (input) => {
  if (!input || typeof input !== 'string') return '';
  return validator.escape(input.trim().substring(0, 2000));
};

const THERAPIST_GUIDELINES = `
You are a supportive, ethical AI companion. Follow these rules:
1. NEVER claim to be a licensed therapist or give medical advice
2. ALWAYS encourage professional help for serious mental health concerns
3. NEVER engage with self-harm, violence, or illegal content
4. Respond with empathy, validation, and reflective listening
5. If user is in crisis, provide resources:
   - US: Text/Call 988
   - International: https://www.befrienders.org
`;

app.post('/api/generate', async (req, res) => {
  const user = await getUserFromSession(req);
  if (!user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { prompt, mode } = req.body;
  const FREE_TIER_LIMIT = 5.0;
  const { isAdmin, usage: currentUsage } = user;

  if (!isAdmin && currentUsage > 0) {
    return res.status(402).json({ error: 'Payment required. Only admin gets free tier.' });
  }
  if (isAdmin && currentUsage >= FREE_TIER_LIMIT) {
    return res.status(402).json({ error: 'Admin free tier ($5) exhausted.' });
  }

  const cleanPrompt = sanitizeInput(prompt);
  if (!cleanPrompt) {
    return res.status(400).json({ error: 'Invalid prompt' });
  }

  let systemMessage = "You are a helpful, professional AI assistant.";
  if (mode === 'therapist') {
    systemMessage = THERAPIST_GUIDELINES;
  } else if (mode === 'code') {
    systemMessage = "You are a senior software engineer. Generate secure, efficient, well-documented code.";
  } else if (mode === 'data') {
    systemMessage = "Generate high-quality synthetic training data in JSON format with realistic distributions.";
  }

  try {
    const completion = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [
        { role: "system", content: systemMessage },
        { role: "user", content: cleanPrompt }
      ],
      temperature: mode === 'therapist' ? 0.8 : 0.7,
      max_tokens: 1000
    });

    const cost = calculateCost(
      completion.usage.prompt_tokens,
      completion.usage.completion_tokens
    );
    
    const newUsage = user.usage + cost;
    await User.findByIdAndUpdate(user._id, { usage: newUsage });

    res.json({
      success: true,
      content: completion.choices[0].message.content,
      cost: parseFloat(cost.toFixed(4)),
      newUsage: parseFloat(newUsage.toFixed(4))
    });

  } catch (error) {
    console.error('OpenAI Error:', error.message);
    res.status(500).json({ 
      error: 'AI generation failed',
      details: error.type === 'insufficient_quota' ? 'API quota exceeded' : 'Processing error'
    });
  }
});

// Start server
const server = app.listen(PORT, async () => {
  console.log(`🚀 Server running on port ${PORT}`);
  
  try {
    const adminEmail = process.env.USER;
    const adminExists = await User.exists({ email: adminEmail });
    if (!adminExists) {
      await new User({
        email: adminEmail,
        password: process.env.PASSWORD,
        name: 'Admin'
      }).save();
      console.log('✅ Created admin account:', adminEmail);
    }
  } catch (err) {
    console.error('Admin creation failed:', err.message);
  }
});

process.on('SIGTERM', () => {
  server.close(() => process.exit(0));
});
