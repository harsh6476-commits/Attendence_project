const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const passport = require('passport');
const User = require('../models/User');
const { protect } = require('../middleware/auth');

// ─── Helpers ────────────────────────────────────────────────────────────────

const ALLOWED_DOMAIN = '@iiitdwd.ac.in';

const isValidEmail = (email) =>
  typeof email === 'string' && email.toLowerCase().endsWith(ALLOWED_DOMAIN);

const isStrongPassword = (password) => {
  if (!password || password.length < 8) return false;
  const hasUpper   = /[A-Z]/.test(password);
  const hasLower   = /[a-z]/.test(password);
  const hasNumber  = /[0-9]/.test(password);
  const hasSpecial = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?`~]/.test(password);
  return hasUpper && hasLower && hasNumber && hasSpecial;
};

const generateToken = (user) => {
  return jwt.sign(
    {
      id: user._id,
      email: user.email,
      role: user.role,
      username: user.username
    },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );
};

// ─── POST /api/auth/signup ──────────────────────────────────────────────────

router.post('/signup', async (req, res) => {
  try {
    const { email, password, role } = req.body;

    // Validate required fields
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email and password are required'
      });
    }

    // Validate email domain
    if (!isValidEmail(email)) {
      return res.status(400).json({
        success: false,
        message: `Only ${ALLOWED_DOMAIN} email addresses are allowed`
      });
    }

    // Validate password strength
    if (!isStrongPassword(password)) {
      return res.status(400).json({
        success: false,
        message:
          'Password must be at least 8 characters and include an uppercase letter, a lowercase letter, a number, and a special character'
      });
    }

    // Check for existing user
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: 'An account with this email already exists'
      });
    }

    // Extract username from email prefix
    const username = email.split('@')[0].toLowerCase();

    // Create user
    const user = await User.create({
      username,
      email: email.toLowerCase(),
      password,
      role: role === 'teacher' ? 'teacher' : 'student'
    });

    const token = generateToken(user);

    res.status(201).json({
      success: true,
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role
      }
    });
  } catch (err) {
    console.error('Signup Error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ─── POST /api/auth/signin ──────────────────────────────────────────────────

router.post('/signin', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email and password are required'
      });
    }

    if (!isValidEmail(email)) {
      return res.status(400).json({
        success: false,
        message: `Only ${ALLOWED_DOMAIN} email addresses are allowed`
      });
    }

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'No account found with this email. Please sign up first.'
      });
    }

    // If user signed up with Google only (no password set)
    if (!user.password) {
      return res.status(401).json({
        success: false,
        message:
          'This account was created with Google Sign-In. Please use the "Sign in with Google" button.'
      });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    const token = generateToken(user);

    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role
      }
    });
  } catch (err) {
    console.error('Signin Error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ─── GET /api/auth/google ───────────────────────────────────────────────────

router.get('/google', (req, res, next) => {
  // Store selected role in session so the Passport callback can read it
  req.session.authRole = req.query.role || 'student';
  passport.authenticate('google', {
    scope: ['profile', 'email'],
    prompt: 'select_account'
  })(req, res, next);
});

// ─── GET /api/auth/google/callback ──────────────────────────────────────────

router.get(
  '/google/callback',
  passport.authenticate('google', {
    failureRedirect: '/signin.html?error=google_auth_failed'
  }),
  (req, res) => {
    // Issue JWT and redirect to welcome page
    const token = generateToken(req.user);
    res.redirect(`/welcome.html?token=${token}`);
  }
);

// ─── GET /api/auth/me  (protected) ─────────────────────────────────────────

router.get('/me', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    res.json({ success: true, user });
  } catch (err) {
    console.error('Me Error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

module.exports = router;
