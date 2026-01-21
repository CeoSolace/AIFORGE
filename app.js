// app.js — Guaranteed working login → /dashboard
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 3000;

// Validate env
if (!process.env.MONGODB_URI || !process.env.USER || !process.env.PASSWORD) {
  console.error('❌ Missing USER, PASSWORD, or MONGODB_URI in .env');
  process.exit(1);
}

// DB
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => {
    console.error('❌ DB Error:', err.message);
    process.exit(1);
  });

// User model
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

userSchema.methods.comparePassword = async function(candidate) {
  return await bcrypt.compare(candidate, this.password);
};

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
    maxAge: 24 * 60 * 60 * 1000,
    httpOnly: true,
    secure: false // Set to true on Render (HTTPS)
  }
}));

// Simple inline template renderer
const renderLogin = (error = null) => `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Login</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="d-flex align-items-center justify-content-center min-vh-100 bg-light">
  <div class="col-md-4">
    <div class="card p-4 shadow">
      <h3 class="text-center mb-4">AIForge Login</h3>
      ${error ? `<div class="alert alert-danger">${error}</div>` : ''}
      <form method="POST">
        <div class="mb-3">
          <input type="email" name="email" class="form-control" placeholder="Email" required>
        </div>
        <div class="mb-3">
          <input type="password" name="password" class="form-control" placeholder="Password" required>
        </div>
        <button type="submit" class="btn btn-primary w-100">Login</button>
      </form>
      <div class="text-center mt-3">
        <small>Admin: ${process.env.USER}</small>
      </div>
    </div>
  </div>
</body>
</html>
`;

const renderDashboard = (user) => `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Dashboard</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
  <nav class="navbar navbar-dark bg-primary">
    <div class="container">
      <span class="navbar-brand">AIForge Dashboard</span>
      <form action="/logout" method="POST">
        <button type="submit" class="btn btn-light btn-sm">Logout</button>
      </form>
    </div>
  </nav>
  <div class="container py-5">
    <h2>Welcome, ${user.email}!</h2>
    <p>You are now logged in and can use AI features.</p>
    <div class="alert alert-success">
      ✅ Login successful! You've been redirected to /dashboard.
    </div>
  </div>
</body>
</html>
`;

// Routes
app.get('/', (req, res) => {
  res.redirect('/login');
});

app.get('/login', (req, res) => {
  console.log('➡️ Rendering login page');
  res.send(renderLogin());
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  console.log('🔐 Login attempt:', email);
  
  try {
    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      console.log('❌ User not found');
      return res.send(renderLogin('Invalid email or password'));
    }

    // Check password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      console.log('❌ Password mismatch');
      return res.send(renderLogin('Invalid email or password'));
    }

    // Save session
    req.session.userId = user._id.toString();
    req.session.save((err) => {
      if (err) {
        console.error('	Session save error:', err);
        return res.send(renderLogin('Session error. Please try again.'));
      }
      
      console.log('✅ Session saved, redirecting to /dashboard');
      res.redirect('/dashboard'); // ✅ GUARANTEED REDIRECT
    });

  } catch (err) {
    console.error('🔥 Login error:', err);
    res.send(renderLogin('Server error. Please try again.'));
  }
});

app.get('/dashboard', async (req, res) => {
  console.log('➡️ Accessing /dashboard, session:', req.session.userId);
  
  if (!req.session.userId) {
    console.log('⚠️ No session, redirecting to login');
    return res.redirect('/login');
  }

  try {
    const user = await User.findById(req.session.userId);
    if (!user) {
      console.log('⚠️ User not found in DB, destroying session');
      req.session.destroy();
      return res.redirect('/login');
    }
    
    console.log('✅ Rendering dashboard for:', user.email);
    res.send(renderDashboard(user));
  } catch (err) {
    console.error('Dashboard error:', err);
    res.redirect('/login');
  }
});

app.post('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

// Create admin user on startup
const createAdmin = async () => {
  const adminEmail = process.env.USER;
  const adminExists = await User.exists({ email: adminEmail });
  
  if (!adminExists) {
    const admin = new User({
      email: adminEmail,
      password: process.env.PASSWORD
    });
    await admin.save();
    console.log('✅ Created admin user:', adminEmail);
  } else {
    console.log('ℹ️ Admin user already exists');
  }
};

// Start server
app.listen(PORT, async () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  await createAdmin();
});
