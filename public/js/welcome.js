// ═══════════════════════════════════════════════════════════════════════════
// IIIT Dharwad Attendance Portal — Welcome Page Logic
// ═══════════════════════════════════════════════════════════════════════════

const loadingState   = document.getElementById('loadingState');
const welcomeContent = document.getElementById('welcomeContent');
const usernameEl     = document.getElementById('usernameDisplay');
const roleBadgeEl    = document.getElementById('roleBadge');

// ── Check for token in URL (Google OAuth callback) ────────────────────────
const urlParams = new URLSearchParams(window.location.search);
const urlToken  = urlParams.get('token');

if (urlToken) {
  localStorage.setItem('token', urlToken);
  // Clean the token from the URL for security
  window.history.replaceState({}, document.title, '/welcome.html');
}

// ── Get stored token ──────────────────────────────────────────────────────
const token = localStorage.getItem('token');

if (!token) {
  // Not logged in — redirect to sign in
  window.location.replace('/signin.html');
} else {
  loadUser();
}

// ── Load user info ────────────────────────────────────────────────────────
async function loadUser() {
  try {
    const res = await fetch('/api/auth/me', {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });

    if (!res.ok) {
      // Token is invalid or expired
      localStorage.removeItem('token');
      window.location.replace('/signin.html');
      return;
    }

    const data = await res.json();
    const user = data.user;

    // Display user info
    usernameEl.textContent = user.username || user.email.split('@')[0];
    roleBadgeEl.textContent = user.role === 'teacher' ? '👨‍🏫 Teacher' : '🎓 Student';

    // Show welcome content, hide loading
    loadingState.style.display   = 'none';
    welcomeContent.style.display = 'block';

  } catch (err) {
    console.error('Failed to load user:', err);
    localStorage.removeItem('token');
    window.location.replace('/signin.html');
  }
}

// ── Logout ────────────────────────────────────────────────────────────────
function logout() {
  localStorage.removeItem('token');
  window.location.replace('/signin.html');
}
