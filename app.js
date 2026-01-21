// app.js — Full AI Platform: Only theceoion@gmail.com is admin with $5 free credit
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const { OpenAI } = require('openai');

const app = express();
const PORT = process.env.PORT || 3000;
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;

// Validate OpenAI key
if (!OPENAI_API_KEY) {
  console.error('❌ Missing OPENAI_API_KEY in .env');
  process.exit(1);
}

const openai = new OpenAI({ apiKey: OPENAI_API_KEY });

// === MONGODB ===
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch(err => {
    console.error('❌ DB Connection Failed:', err);
    process.exit(1);
  });

// === USER MODEL ===
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  name: { type: String, required: true },
  usage: { type: Number, default: 0 } // USD
});

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

userSchema.methods.comparePassword = async function(candidate) {
  return await bcrypt.compare(candidate, this.password);
};

// 👑 ADMIN CHECK: ONLY theceoion@gmail.com
userSchema.virtual('isAdmin').get(function() {
  return this.email === 'theceoion@gmail.com';
});

userSchema.set('toJSON', { virtuals: true });
const User = mongoose.model('User', userSchema);

// === MIDDLEWARE ===
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.set('view engine', 'ejs');

app.use(session({
  secret: process.env.SESSION_SECRET || 'fallback-secret-change-in-prod',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: process.env.MONGODB_URI }),
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

// === AUTH GUARD ===
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  User.findById(req.session.userId).lean()
    .then(user => {
      if (!user) throw new Error('User not found');
      req.user = user;
      next();
    })
    .catch(() => {
      req.session.destroy();
      res.redirect('/login');
    });
}

// === COST CALCULATION (gpt-4o pricing) ===
const calculateCost = (promptTokens, completionTokens) => {
  const inputCost = (promptTokens / 1_000_000) * 2.50;   // $2.50 / 1M input tokens
  const outputCost = (completionTokens / 1_000_000) * 10.00; // $10.00 / 1M output tokens
  return parseFloat((inputCost + outputCost).toFixed(4));
};

// === ROUTES ===
app.get('/', async (req, res) => {
  let user = null, usage = 0, isAdmin = false;
  if (req.session.userId) {
    try {
      const u = await User.findById(req.session.userId).lean();
      if (u) ({ usage, isAdmin } = u);
      user = u;
    } catch (err) {
      req.session.destroy();
    }
  }
  res.render('index', { user, usage, isAdmin });
});

app.get('/login', (req, res) => res.render('login', { error: null }));

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email: email?.toLowerCase().trim() });
    if (!user || !(await user.comparePassword(password))) {
      return res.render('login', { error: 'Invalid email or password' });
    }
    req.session.userId = user._id.toString();
    res.redirect('/');
  } catch (err) {
    res.render('login', { error: 'Server error. Try again.' });
  }
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

// === AI GENERATION (PROTECTED) ===
app.post('/api/generate', requireAuth, async (req, res) => {
  const { prompt, task } = req.body;
  const FREE_TIER_LIMIT = 5.0;
  const { isAdmin, usage: currentUsage } = req.user;

  // 🔒 PAYMENT ENFORCEMENT
  if (!isAdmin && currentUsage > 0) {
    return res.status(402).json({ error: 'Payment required. Only admin gets free tier.' });
  }
  if (isAdmin && currentUsage >= FREE_TIER_LIMIT) {
    return res.status(402).json({ error: 'Admin free tier ($5) exhausted.' });
  }

  // Build prompt
  const systemPrompts = {
    code: "You are a senior engineer. Generate production-ready, secure, documented code.",
     "Generate high-quality synthetic training data in JSON format.",
    file: "Analyze and summarize the provided content with key insights.",
    story: "Write a creative, unfiltered narrative as requested."
  };

  try {
    const completion = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [
        { role: "system", content: systemPrompts[task] || systemPrompts.story },
        { role: "user", content: prompt }
      ],
      temperature: 0.7,
      max_tokens: 1000
    });

    const cost = calculateCost(
      completion.usage.prompt_tokens,
      completion.usage.completion_tokens
    );
    
    const newUsage = req.user.usage + cost;
    await User.findByIdAndUpdate(req.user._id, { usage: newUsage });

    res.json({
      success: true,
      content: completion.choices[0].message.content,
      cost: parseFloat(cost.toFixed(4)),
      newUsage: parseFloat(newUsage.toFixed(4))
    });

  } catch (error) {
    console.error('OpenAI Error:', error.message);
    res.status(500).json({ error: 'AI generation failed', details: error.message });
  }
});

// === EJS TEMPLATES (INLINED) ===
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
      <small>© 2026 AIForge • Only theceoion@gmail.com is admin with $5 free credit</small>
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
    <h1 class="display-5 fw-bold">AI for <span class="text-primary">Business</span> & <span class="text-success">Esports</span></h1>
    <p class="lead">Code, data, analysis, stories — powered by OpenAI</p>
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

          <form id="aiForm" class="mt-4">
            <div class="mb-3">
              <select class="form-select" name="task" required>
                <option value="code">Professional Code Generation</option>
                <option value="data">Training Data Creation</option>
                <option value="file">File/Content Analysis</option>
                <option value="story">Unfiltered Storytelling</option>
              </select>
            </div>
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
document.getElementById('aiForm')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = e.submitter;
  const original = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span> Processing...';

  try {
    const res = await fetch('/api/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(Object.fromEntries(new FormData(e.target)))
    });
    const data = await res.json();
    
    if (res.ok) {
      document.getElementById('result').textContent = data.content;
      document.getElementById('result').style.display = 'block';
      setTimeout(() => location.reload(), 2000); // Refresh usage
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
        <small class="text-muted">Only theceoion@gmail.com is admin with $5 free credit</small>
      </div>
    </div>
  </div>
</div>
  `
};

app.engine('ejs', (path, opts, cb) => {
  const name = path.split('/').pop().replace('.ejs', '');
  if (templates[name]) {
    const body = ejs.render(templates[name], opts);
    const html = ejs.render(templates.layout, { ...opts, body });
    cb(null, html);
  } else cb(new Error('Template not found'));
});

// === START SERVER + CREATE ADMIN ===
app.listen(PORT, async () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  
  // Auto-create admin account
  const adminEmail = 'theceoion@gmail.com';
  const existing = await User.exists({ email: adminEmail });
  if (!existing) {
    await new User({
      email: adminEmail,
      password: 'CuntFucked26!', // ⚠️ CHANGE THIS IN PRODUCTION!
      name: 'CEO'
    }).save();
    console.log('✅ Created admin account:', adminEmail);
  }
});
