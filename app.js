// app.js — Full AI Chat Dashboard with OpenAI Integration
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
    console.error(`❌ Missing ${key} in .env`);
    process.exit(1);
  }
}

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// DB
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch(err => {
    console.error('❌ DB Error:', err.message);
    process.exit(1);
  });

// User model
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  name: { type: String, default: 'User' },
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

app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: process.env.MONGODB_URI }),
  cookie: { 
    maxAge: 7 * 24 * 60 * 60 * 1000,
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production'
  }
}));

// ✅ INLINE TEMPLATES
const renderTemplate = (templateName, options = {}) => {
  const ejs = require('ejs');
  
  const templates = {
    layout: `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>AIForge | Chat</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"/>
  <style>
    :root { --primary: #6c5ce7; }
    body { background: #f8f9fa; min-height: 100vh; }
    .navbar-brand { font-weight: 700; color: var(--primary) !important; }
    .chat-container { max-width: 900px; margin: 0 auto; }
    .chat-box { 
      height: 500px; 
      overflow-y: auto; 
      border: 1px solid #dee2e6; 
      border-radius: 12px; 
      padding: 20px; 
      background: white; 
      margin-bottom: 15px;
    }
    .message { 
      margin-bottom: 15px; 
      padding: 12px 16px; 
      border-radius: 18px; 
      max-width: 80%;
      word-wrap: break-word;
    }
    .user-message { 
      background: #e3f2fd; 
      margin-left: auto; 
      border-bottom-right-radius: 5px;
    }
    .ai-message { 
      background: #f1f8e9; 
      margin-right: auto; 
      border-bottom-left-radius: 5px;
    }
    .usage-bar { 
      height: 8px; 
      background: #e9ecef; 
      border-radius: 4px; 
      margin: 8px 0; 
      overflow: hidden; 
    }
    .usage-fill { 
      height: 100%; 
      border-radius: 4px; 
    }
    .mode-btn { 
      transition: all 0.2s; 
      border: 1px solid #ced4da;
    }
    .mode-btn.active { 
      background: var(--primary); 
      color: white; 
      border-color: var(--primary);
    }
    .typing-indicator {
      display: none;
      padding: 10px;
      color: #6c757d;
    }
  </style>
</head>
<body>
  <nav class="navbar navbar-light bg-white shadow-sm">
    <div class="container d-flex justify-content-between">
      <a class="navbar-brand" href="/dashboard"><i class="fas fa-comments me-2"></i>AIForge Chat</a>
      <div>
        <% if (locals.user) { %>
          <span><b><%= user.name %></b> 
            <% if (isAdmin) { %>
              <span class="badge bg-primary">ADMIN</span>
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
  <footer class="bg-light py-3 mt-4">
    <div class="container text-center">
      <small>© 2026 AIForge • Only admin gets $5 free credit</small>
    </div>
  </footer>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
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
    `,
    
    dashboard: `
<% const FREE_LIMIT = 5; %>
<div class="container chat-container py-4">
  <div class="d-flex justify-content-between align-items-center mb-3">
    <h4><i class="fas fa-robot me-2"></i>AI Assistant</h4>
    <% if (isAdmin) { %>
      <span class="badge bg-success">Free Tier: $5</span>
    <% } else { %>
      <span class="badge bg-warning">Paid Plan</span>
    <% } %>
  </div>

  <p class="mb-2">Usage: $<%= usage.toFixed(4) %> 
    <% if (isAdmin) { %>
      / $<%= FREE_LIMIT %>
    <% } %>
  </p>

  <% if (isAdmin) { %>
    <div class="usage-bar">
      <div class="usage-fill bg-success" style="width: <%= Math.min(100, (usage / FREE_LIMIT) * 100) %>%"></div>
    </div>
  <% } %>

  <% if ((isAdmin && usage >= FREE_LIMIT) || (!isAdmin && usage > 0)) { %>
    <div class="alert alert-warning mb-3">
      <i class="fas fa-exclamation-triangle me-2"></i>
      <%= isAdmin ? 'Free tier exhausted' : 'Payment required' %>
    </div>
  <% } %>

  <!-- Mode selector -->
  <div class="mb-3">
    <div class="btn-group" role="group">
      <button type="button" class="btn btn-outline-primary mode-btn active" data-mode="general">General</button>
      <button type="button" class="btn btn-outline-success mode-btn" data-mode="code">Code</button>
      <button type="button" class="btn btn-outline-info mode-btn" data-mode="data">Data</button>
      <button type="button" class="btn btn-outline-warning mode-btn" data-mode="therapist">Therapist</button>
    </div>
    <input type="hidden" id="modeInput" value="general">
  </div>

  <!-- Chat box -->
  <div class="chat-box" id="chatBox">
    <div class="message ai-message">
      Hello! I'm your AI assistant. How can I help you today?
    </div>
  </div>

  <!-- Typing indicator -->
  <div class="typing-indicator" id="typingIndicator">
    <i class="fas fa-circle-notch fa-spin me-2"></i> AI is thinking...
  </div>

  <!-- Input form -->
  <form id="chatForm" class="mt-2">
    <div class="input-group">
      <input type="text" class="form-control" id="userInput" placeholder="Type your message..." required
        <%= ((isAdmin && usage >= FREE_LIMIT) || (!isAdmin && usage > 0)) ? 'disabled' : '' %>>
      <button class="btn btn-primary" type="submit"
        <%= ((isAdmin && usage >= FREE_LIMIT) || (!isAdmin && usage > 0)) ? 'disabled' : '' %>>
        Send
      </button>
    </div>
  </form>
</div>

<script>
let chatHistory = [];

document.querySelectorAll('.mode-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.mode-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('modeInput').value = btn.dataset.mode;
  });
});

document.getElementById('chatForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const userInput = document.getElementById('userInput').value.trim();
  const mode = document.getElementById('modeInput').value;
  
  if (!userInput) return;

  // Add user message
  addMessageToChat(userInput, 'user');
  document.getElementById('userInput').value = '';
  
  // Show typing indicator
  document.getElementById('typingIndicator').style.display = 'block';
  const sendBtn = document.querySelector('#chatForm button');
  sendBtn.disabled = true;

  try {
    const res = await fetch('/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: userInput, mode })
    });
    
    const data = await res.json();
    
    document.getElementById('typingIndicator').style.display = 'none';
    
    if (res.ok) {
      addMessageToChat(data.response, 'ai');
      // Auto-scroll
      const chatBox = document.getElementById('chatBox');
      chatBox.scrollTop = chatBox.scrollHeight;
    } else {
      addMessageToChat('Error: ' + (data.error || 'Unknown'), 'ai');
    }
  } catch (err) {
    document.getElementById('typingIndicator').style.display = 'none';
    addMessageToChat('Network error: ' + err.message, 'ai');
  } finally {
    sendBtn.disabled = false;
  }
});

function addMessageToChat(text, sender) {
  const chatBox = document.getElementById('chatBox');
  const messageDiv = document.createElement('div');
  messageDiv.className = sender === 'user' ? 'message user-message' : 'message ai-message';
  messageDiv.textContent = text;
  chatBox.appendChild(messageDiv);
  chatBox.scrollTop = chatBox.scrollHeight;
}
</script>
    `
  };

  if (!templates[templateName]) {
    throw new Error(`Template not found: ${templateName}`);
  }

  const body = ejs.render(templates[templateName], { ...options, locals: options });
  return ejs.render(templates.layout, { ...options, body, locals: options });
};

// Get user helper
async function getUserFromSession(req) {
  if (!req.session || !req.session.userId) return null;
  try {
    return await User.findById(req.session.userId).lean();
  } catch (err) {
    req.session.destroy();
    return null;
  }
}

// Routes
app.get('/', (req, res) => res.redirect('/login'));

app.get('/login', (req, res) => {
  res.send(renderTemplate('login', { error: null }));
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email: email?.toLowerCase().trim() });
    if (!user || !(await user.comparePassword(password))) {
      return res.send(renderTemplate('login', { error: 'Invalid credentials' }));
    }
    req.session.userId = user._id.toString();
    req.session.save(() => {
      res.redirect('/dashboard'); // ✅ Redirect after session save
    });
  } catch (err) {
    res.send(renderTemplate('login', { error: 'Server error' }));
  }
});

app.get('/dashboard', async (req, res) => {
  const user = await getUserFromSession(req);
  if (!user) return res.redirect('/login');
  
  res.send(renderTemplate('dashboard', { 
    user, 
    usage: user.usage, 
    isAdmin: user.isAdmin 
  }));
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// ✅ CHAT API ENDPOINT
const calculateCost = (promptTokens, completionTokens) => {
  const inputCost = (promptTokens / 1_000_000) * 2.50;   // gpt-4o input
  const outputCost = (completionTokens / 1_000_000) * 10.00; // gpt-4o output
  return parseFloat((inputCost + outputCost).toFixed(4));
};

const sanitizeInput = (input) => {
  if (!input || typeof input !== 'string') return '';
  return validator.escape(input.trim().substring(0, 2000));
};

const SYSTEM_PROMPTS = {
  therapist: `
You are a supportive, ethical AI companion. Follow these rules:
1. NEVER claim to be a licensed therapist or give medical advice
2. ALWAYS encourage professional help for serious mental health concerns
3. NEVER engage with self-harm, violence, or illegal content
4. Respond with empathy, validation, and reflective listening
5. If user is in crisis, provide resources:
   - US: Text/Call 988
   - International: https://www.befrienders.org
`,
  code: "You are a senior software engineer. Generate secure, efficient, well-documented code in any language.",
  data: "Generate high-quality synthetic training data in JSON format with realistic distributions.",
  general: "You are a helpful, professional AI assistant."
};

app.post('/api/chat', async (req, res) => {
  const user = await getUserFromSession(req);
  if (!user) return res.status(401).json({ error: 'Unauthorized' });

  const { message, mode = 'general' } = req.body;
  const FREE_TIER_LIMIT = 5.0;
  const { isAdmin, usage: currentUsage } = user;

  // Payment enforcement
  if (!isAdmin && currentUsage > 0) {
    return res.status(402).json({ error: 'Payment required. Only admin gets free tier.' });
  }
  if (isAdmin && currentUsage >= FREE_TIER_LIMIT) {
    return res.status(402).json({ error: 'Admin free tier ($5) exhausted.' });
  }

  const cleanMessage = sanitizeInput(message);
  if (!cleanMessage) {
    return res.status(400).json({ error: 'Invalid message' });
  }

  const systemMessage = SYSTEM_PROMPTS[mode] || SYSTEM_PROMPTS.general;

  try {
    const completion = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [
        { role: "system", content: systemMessage },
        { role: "user", content: cleanMessage }
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
      response: completion.choices[0].message.content,
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

// Create admin on startup
const createAdmin = async () => {
  const adminEmail = process.env.USER;
  const existing = await User.exists({ email: adminEmail });
  if (!existing) {
    await new User({
      email: adminEmail,
      password: process.env.PASSWORD,
      name: 'Admin'
    }).save();
    console.log('✅ Created admin:', adminEmail);
  }
};

// Start server
const server = app.listen(PORT, async () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  await createAdmin();
});

process.on('SIGTERM', () => {
  server.close(() => process.exit(0));
});
