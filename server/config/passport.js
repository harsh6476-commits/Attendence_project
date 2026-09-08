const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const User = require('../models/User');

// Serialize user ID into session
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Deserialize user from session by ID
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// Google OAuth 2.0 Strategy
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: '/api/auth/google/callback',
      passReqToCallback: true
    },
    async (req, accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails && profile.emails[0] && profile.emails[0].value;

        if (!email) {
          return done(null, false, { message: 'No email found in Google profile' });
        }

        // Only allow @iiitdwd.ac.in emails
        if (!email.endsWith('@iiitdwd.ac.in')) {
          return done(null, false, {
            message: 'Only @iiitdwd.ac.in email addresses are allowed. Please use your IIIT Dharwad email.'
          });
        }

        const username = email.split('@')[0];

        // Role passed via session (set before redirect to Google)
        const role = req.session.authRole || 'student';

        // Check if user already exists by Google ID
        let user = await User.findOne({ googleId: profile.id });

        if (user) {
          return done(null, user);
        }

        // Check if user exists by email (signed up manually before)
        user = await User.findOne({ email });

        if (user) {
          // Link Google account to existing manual account
          user.googleId = profile.id;
          user.displayName = profile.displayName || username;
          await user.save();
          return done(null, user);
        }

        // Create brand new user
        user = await User.create({
          username,
          email,
          googleId: profile.id,
          displayName: profile.displayName || username,
          role
        });

        return done(null, user);
      } catch (err) {
        console.error('Google OAuth Error:', err);
        return done(err, null);
      }
    }
  ));
} else {
  console.warn('⚠️  Google OAuth disabled: GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET missing in environment.');
}
