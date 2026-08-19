require('dotenv').config();
const express = require('express');
const cors = require('cors');
const session = require('express-session');
const passport = require('passport');
const path = require('path');
const connectDB = require('./config/db');

// Connect to MongoDB
connectDB();

// Load Passport config
require('./config/passport');

const app = express();

// --------------- Middleware ---------------
app.use(cors({
  origin: process.env.CLIENT_URL || 'http://localhost:3000',
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 24 * 60 * 60 * 1000, // 1 day
    secure: false                  // set true in production with HTTPS
  }
}));

app.use(passport.initialize());
app.use(passport.session());

// --------------- Static Files ---------------
app.use(express.static(path.join(__dirname, '..', 'public')));

// --------------- API Routes ---------------
app.use('/api/auth', require('./routes/auth'));

// --------------- Catch-all: serve index.html ---------------
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

// --------------- Start Server ---------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n  🚀  Server running at http://localhost:${PORT}`);
  console.log(`  📚  IIIT Dharwad Attendance Portal\n`);
});
