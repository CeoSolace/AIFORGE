// app.js — Complete AI Platform with OpenAI + MongoDB + Free Tier Logic
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const { OpenAI } = require('openai');

const app = express();
const PORT = process.env.PORT || 3000;

// === OPENAI SETUP ===
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

// === MONGODB SETUP ===
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch(err => console.error('❌ DB Error:', err));

// === USER MODEL ===
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  name: { type: String, required: true },
  usage: { type: Number, default: 0 } // in USD
});

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

userSchema.methods.comparePassword = async function(candidate) {
  return await bcrypt.compare(candidate, this.password);
};

userSchema.virtual('isEligibleForFreeTier').get(function() {
  return this.email === 'theceoion@gmail.com';
});

userSchema.set('toJSON', { virtuals: true });
const User = mongoose.model('User', userSchema);

// === MIDDLEWARE ===
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.set('view engine', 'ejs');

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: process.env.MONGODB_URI }),
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

// === AUTH MIDDLEWARE ===
async function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  try {
    req.user = await User.findById(req.session.userId).lean();
    if (!req.user) throw new Error('User not found');
    next();
  } catch (err) {
    req.session.destroy();
    res.redirect('/login');
  }
}

// === COST CALCULATION (USD per 1M tokens) ===
const COST_PER_1M_INPUT = 2.50;   // gpt-4o input
const COST_PER_1M_OUTPUT = 10.00; // gpt-4o output

function calculateCost(promptTokens, completionTokens) {
  const inputCost = (promptTokens / 1_000_000) * COST_PER_1M_INPUT;
  const outputCost = (completionTokens / 1_000_000) * COST_PER_1M_OUTPUT;
  return parseFloat((inputCost + outputCost).toFixed(4));
}

// === ROUTES ===
app.get('/', async (req, res) => {
  let user = null, usage = 0, isEligible = false;
  if (req.session.userId) {
    try {
      const u = await User.findById(req.session.userId).lean();
      if (u) {
        user = u;
        usage = u.usage;
        isEligible = u.isEligibleForFreeTier;
      }
    } catch (err) {
      req.session.destroy();
    }
  }
  res.render('index', { user, usage, isEligible });
});

app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email: email?.toLowerCase().trim() });
    if (!user || !(await user.comparePassword(password))) {
      return res.render('login', { error: 'Invalid credentials' });
    }
    req.session.userId = user._id.toString();
    res.redirect('/');
  } catch (err) {
    res.render('login', { error: 'Server error' });
  }
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

// === AI GENERATION ENDPOINT ===
app.post('/api/generate', requireAuth, async (req, res) => {
  const { prompt, task } = req.body;
  const FREE_LIMIT = 5.00;
  const isEligible = req.user.isEligibleForFreeTier;

  // Check payment status
  if (!isEligible && req.user.usage > 0) {
    return res.status(402).json({ error: 'Payment required for non-eligible accounts' });
  }
  if (isEligible && req.user.usage >= FREE_LIMIT) {
    return res.status(402).json({ error: 'Free tier ($5) exhausted' });
  }

  // Build system prompt based on task
  const systemPrompts = {
    code: "You are a senior software engineer. Generate professional, production-ready code with best practices, error handling, and documentation.",
    data: "You are a data scientist. Generate high-quality synthetic training data in JSON format with realistic distributions.",
    file: "You are an AI analyst. Summarize and extract key insights from the provided content.",
    story: "You are a creative writer. Generate an unfiltered, unrestricted narrative as requested."
  };

  const systemMessage = systemPrompts[task] || systemPrompts.story;

  try {
    // Call OpenAI API
    const completion = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [
        { role: "system", content: systemMessage },
        { role: "user", content: prompt }
      ],
      temperature: 0.7,
      max_tokens: 1000
    });

    // Calculate cost
    const usage = completion.usage;
    const cost = calculateCost(usage.prompt_tokens, usage.completion_tokens);
    const newTotalUsage = req.user.usage + cost;

    // Save to DB
    await User.findByIdAndUpdate(req.user._id, { usage: newTotalUsage });

    res.json({
      success: true,
      content: completion.choices[0].message.content,
      cost: parseFloat(cost.toFixed(4)),
      newUsage: parseFloat(newTotalUsage.toFixed(4)),
      remainingCredit: isEligible ? Math.max(0, FREE_LIMIT - newTotalUsage).toFixed(4) : '0.0000'
    });

  } catch (error) {
    console.error('OpenAI Error:', error);
    res.status(500).json({ 
      error: 'AI generation failed', 
      details: error.message 
    });
  }
});

// === EJS TEMPLATES (INLINED) ===
const templates = {
  layout: `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>AIForge | Business & Esports AI</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"/>
  <style>
    :root { --primary: #6c5ce7; }
    body { background: linear-gradient(135deg, #f8f9ff, #eef2ff); min-height: 100vh; }
    .navbar-brand { font-weight: 700; color: var(--primary) !important; }
    .card { border-radius: 16px; box-shadow: 0 4px 20px rgba(0,0,0,0.06); border: none; }
    .usage-meter { height: 12px; background: #e9ecef; border-radius: 6px; overflow: hidden; margin: 10px 0; }
    .usage-fill { height: 100%; border-radius: 6px; }
    .result-box { background: #f8f9fa; border-left: 4px solid var(--primary); padding: 15px; margin-top: 20px; }
  </style>
</head>
<body>
  <nav class="navbar navbar-light bg-white shadow-sm">
    <div class="container">
      <a class="navbar-brand" href="/"><i class="fas fa-bolt me-2"></i>AIForge</a>
      <div>
        <% if (locals.user) { %>
          <span class="me-3">Hi, <b><%= user.name %></b></span>
          <form action="/logout" method="POST" class="d-inline">
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
      <small>© 2026 AIForge • Only theceoion@gmail.com gets $5 free credit</small>
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
    <p class="lead">Generate code, training data, analyze files, or create unfiltered stories</p>
  </div>

  <% if (!user) { %>
    <div class="alert alert-info text-center">Please <a href="/login">log in</a> to use AI features</div>
  <% } else { %>
    <div class="row justify-content-center">
      <div class="col-md-8">
        <div class="card p-4">
          <div class="d-flex justify-content-between mb-3">
            <h5>Usage Dashboard</h5>
            <% if (isEligible) { %>
              <span class="badge bg-success">Free Tier: $5</span>
            <% } else { %>
              <span class="badge bg-warning">Paid Plan</span>
            <% } %>
          </div>
          
          <p>Used: <b>$<%= usage.toFixed(4) %></b></p>
          
          <% if (isEligible) { %>
            <div class="usage-meter">
              <div class="usage-fill bg-success" style="width: <%= Math.min(100, (usage / FREE_LIMIT) * 100) %>%"></div>
            </div>
            <small class="text-muted">Remaining: $<%= (FREE_LIMIT - usage).toFixed(4) %></small>
          <% } %>

          <% if ((isEligible && usage >= FREE_LIMIT) || (!isEligible && usage > 0)) { %>
            <div class="alert alert-warning mt-3">
              <i class="fas fa-exclamation-triangle me-2"></i>
              <%= isEligible ? 'Free tier used up' : 'Payment required' %>
            </div>
          <% } %>

          <form id="aiForm" class="mt-4">
            <div class="mb-3">
              <select class="form-select" name="task" required>
                <option value="code">Generate Professional Code</option>
                <option value="data">Create Training Data</option>
                <option value="file">Analyze Content</option>
                <option value="story">Write Unfiltered Story</option>
              </select>
            </div>
            <div class="mb-3">
              <textarea class="form-control" name="prompt" rows="4" placeholder="Describe your request in detail..." required></textarea>
            </div>
            <button type="submit" class="btn btn-primary w-100" 
              <%= ((isEligible && usage >= FREE_LIMIT) || (!isEligible && usage > 0)) ? 'disabled' : '' %>>
              <i class="fas fa-bolt me-2"></i> Generate with AI
            </button>
          </form>

          <div id="result" class="mt-4" style="display:none;"></div>
        </div>
      </div>
    </div>
  <% } %>
</div>

<script>
document.getElementById('aiForm')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const form = e.target;
  const submitBtn = form.querySelector('button');
  const originalText = submitBtn.innerHTML;
  
  submitBtn.disabled = true;
  submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Processing...';
  
  try {
    const res = await fetch('/api/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(Object.fromEntries(new FormData(form)))
    });
    
    const data = await res.json();
    
    if (res.ok) {
      document.getElementById('result').innerHTML = 
        '<div class="result-box"><h6>AI Response (Cost: $' + data.cost + ')</h6><pre>' + 
        data.content.replace(/</g, '&lt;').replace(/>/g, '&gt;') + 
        '</pre></div>';
      document.getElementById('result').style.display = 'block';
      
      // Update usage in UI
      location.reload();
    } else {
      alert('Error: ' + (data.error || 'Unknown error'));
    }
  } catch (err) {
    alert('Network error: ' + err.message);
  } finally {
    submitBtn.disabled = false;
    submitBtn.innerHTML = originalText;
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
        <small class="text-muted">Only theceoion@gmail.com gets $5 free credit</small>
      </div>
    </div>
  </div>
</div>
  `
};

// EJS engine with inline templates
app.engine('ejs', (filePath, options, callback) => {
  const viewName = filePath.split('/').pop().replace('.ejs', '');
  if (templates[viewName]) {
    const ejs = require('ejs');
    const body = ejs.render(templates[viewName], options);
    const html = ejs.render(templates.layout, { ...options, body });
    callback(null, html);
  } else {
    callback(new Error('Template not found'));
  }
});

// === CREATE DEFAULT ADMIN USER ON STARTUP ===
app.listen(PORT, async () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  
  // Create admin user if missing
  const adminEmail = 'theceoion@gmail.com';
  const adminExists = await User.exists({ email: adminEmail });
  if (!adminExists) {
    const admin = new User({
      email: adminEmail,
      password: 'SecurePass123!', // CHANGE IN PRODUCTION!
      name: 'CEO'
    });
    await admin.save();
    console.log('✅ Created admin user:', adminEmail);
  }
});
