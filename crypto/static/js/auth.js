/**
 * SecureCrypt — Auth State Manager (auth.js)
 * ─────────────────────────────────────────
 * Single source of truth for user session and user database registry.
 * Uses localStorage with persistent user database (sc_users_db_v1).
 * Load this script BEFORE any page scripts.
 */

const Auth = (() => {
  const SESSION_KEY  = 'sc_user_v1';
  const USERS_DB_KEY = 'sc_users_db_v1';

  /* ── Read / Write User Database ─────────────────────── */
  function _getUsersDb() {
    try { return JSON.parse(localStorage.getItem(USERS_DB_KEY)) || {}; } catch (_) { return {}; }
  }

  function _saveUsersDb(db) {
    try { localStorage.setItem(USERS_DB_KEY, JSON.stringify(db)); } catch (_) {}
  }

  /* ── Save Active Session & Sync to DB ──────────────── */
  function _saveSession(user) {
    try { localStorage.setItem(SESSION_KEY, JSON.stringify(user)); } catch (_) {}
    if (user && user.email) {
      const db = _getUsersDb();
      const emailKey = user.email.toLowerCase().trim();
      const existing = db[emailKey] || {};
      db[emailKey] = Object.assign({}, existing, user);
      _saveUsersDb(db);
    }
  }

  function get() {
    try { return JSON.parse(localStorage.getItem(SESSION_KEY)) || null; } catch (_) { return null; }
  }

  /* ── State checks ───────────────────────────────────── */
  function isLoggedIn() { return !!get(); }

  /* ── Login helpers ──────────────────────────────────── */

  /** Called after email OTP verified */
  function loginWithEmail(name, email, phone) {
    const db = _getUsersDb();
    const existing = db[(email || '').toLowerCase().trim()] || {};
    const finalUser = {
      name: name || existing.name || email.split('@')[0],
      email: email,
      phone: phone || existing.phone || '',
      provider: 'email',
      picture: existing.picture || '',
      at: existing.at || Date.now()
    };
    _saveSession(finalUser);
  }

  /** Called after Google OAuth success — retrieves existing personal details if available */
  function loginWithGoogle(name, email, picture) {
    const db = _getUsersDb();
    const existing = db[(email || '').toLowerCase().trim()] || {};
    const finalUser = {
      name: existing.name || name || email.split('@')[0],
      email: email,
      phone: existing.phone || '',
      provider: 'google',
      picture: picture || existing.picture || '',
      at: existing.at || Date.now()
    };
    _saveSession(finalUser);
  }

  /** Called after signup OTP verified — stores full profile */
  function signUp(name, email, phone) {
    const finalUser = {
      name: name || email.split('@')[0],
      email: email,
      phone: phone || '',
      provider: 'email',
      at: Date.now()
    };
    _saveSession(finalUser);
  }

  /** Update profile fields without logging out */
  function updateProfile(fields) {
    const user = get();
    if (!user) return;
    const updated = Object.assign({}, user, fields);
    _saveSession(updated);
  }

  /* ── Logout ─────────────────────────────────────────── */
  function logout() {
    localStorage.removeItem(SESSION_KEY);
    window.location.href = '/login';
  }

  /* ── Utilities ──────────────────────────────────────── */

  /** "Mohan Kumar" → "MK" */
  function initials(name) {
    if (!name) return '?';
    return name.trim().split(/\s+/).map(w => w[0].toUpperCase()).slice(0, 2).join('');
  }

  /** Redirect to /login if not authenticated */
  function requireAuth() {
    if (!isLoggedIn()) {
      window.location.replace('/login');
      return false;
    }
    return true;
  }

  /** Redirect away from login/signup if already authenticated */
  function redirectIfLoggedIn(dest) {
    if (isLoggedIn()) {
      window.location.replace(dest || '/');
      return true;
    }
    return false;
  }

  return { get, isLoggedIn, loginWithEmail, loginWithGoogle, signUp, updateProfile, logout, initials, requireAuth, redirectIfLoggedIn };
})();
