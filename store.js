/* Gadget Hub shared data + developer login.
   IMPORTANT: this is a browser-only demo. Everything is saved in the browser's localStorage,
   so edits are visible only on the computer that made them until you Export and upload inventory.js.
   The login here keeps casual visitors out. It is NOT real security (anyone can read this file).
   For real security the logins and stock must live on a server (Firebase / Supabase). */
(function () {
  var K = { inv: "gh_inventory_v1", cfg: "gh_config_v1", users: "gh_users_v1", ses: "gh_session_v1", lock: "gh_lock_v1" };

  /* Developers need this code to register. CHANGE IT before you put the site online. */
  var DEV_CODE = "GADGET-DEV-2026";

  /* Camera style + card colours for each known model */
  var MODELS = {
    "iPhone 17":         { cam: "bar2",    b1: "#c9dfbe", b2: "#6a8a63" },
    "iPhone 17 Pro Max": { cam: "plateau", b1: "#ff9a5c", b2: "#d1561f" },
    "iPhone 18 Pro Max": { cam: "plateau", b1: "#8a2442", b2: "#2a0812" },
    "iPhone 16 Pro":     { cam: "tri",     b1: "#e9cfae", b2: "#9b7550" },
    "iPhone 15 Pro Max": { cam: "tri",     b1: "#d8d3c8", b2: "#8a857a" },
    "iPhone 15":         { cam: "dual",    b1: "#f3a9bb", b2: "#b9506e" },
    "iPhone 14 Pro Max": { cam: "tri",     b1: "#4a3a78", b2: "#150f2a" }
  };

  function read(k, f) { try { var v = localStorage.getItem(k); return v === null ? f : JSON.parse(v); } catch (e) { return f; } }
  function write(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); return true; } catch (e) { return false; } }
  function drop(k) { try { localStorage.removeItem(k); } catch (e) {} }
  function clone(o) { return JSON.parse(JSON.stringify(o)); }

  /* ---------- inventory + settings ---------- */
  function getInventory() {
    var saved = read(K.inv, null);
    return saved || clone(window.GH_DEFAULT_INVENTORY || []);
  }
  function saveInventory(list) { return write(K.inv, list); }
  function resetInventory() { drop(K.inv); drop(K.cfg); }
  function hasLocalEdits() { return read(K.inv, null) !== null; }
  function isSample() { return !!window.GH_IS_SAMPLE && !hasLocalEdits(); }
  function config() {
    var d = window.GH_CONFIG || { whatsapp: "91XXXXXXXXXX" };
    var s = read(K.cfg, null);
    var out = {}; var k;
    for (k in d) out[k] = d[k];
    if (s) for (k in s) out[k] = s[k];
    return out;
  }
  function saveConfig(c) { return write(K.cfg, c); }
  function exportJs() {
    return "/* Gadget Hub stock. Replace the old inventory.js with this file, then upload your site again. */\n" +
      "window.GH_IS_SAMPLE = false;\n" +
      "window.GH_CONFIG = " + JSON.stringify(config(), null, 2) + ";\n" +
      "window.GH_DEFAULT_INVENTORY = " + JSON.stringify(getInventory(), null, 2) + ";\n";
  }

  /* ---------- password hashing ---------- */
  var enc = typeof TextEncoder !== "undefined" ? new TextEncoder() : null;
  function toHex(buf) { return Array.prototype.map.call(new Uint8Array(buf), function (b) { return ("0" + b.toString(16)).slice(-2); }).join(""); }
  function rand(n) {
    var a = new Uint8Array(n);
    if (window.crypto && crypto.getRandomValues) crypto.getRandomValues(a);
    else for (var i = 0; i < n; i++) a[i] = Math.floor(Math.random() * 256);
    return toHex(a);
  }
  function hashPw(pw, salt) {
    if (window.crypto && crypto.subtle && enc) {
      return crypto.subtle.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveBits"]).then(function (key) {
        return crypto.subtle.deriveBits({ name: "PBKDF2", salt: enc.encode(salt), iterations: 120000, hash: "SHA-256" }, key, 256);
      }).then(toHex);
    }
    var h = 5381, s = salt + pw;
    for (var i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) | 0;
    return Promise.resolve("w" + (h >>> 0).toString(16));
  }

  /* ---------- accounts ---------- */
  function users() { return read(K.users, []); }
  function fail(msg) { return { ok: false, error: msg }; }
  function startSession(email) { write(K.ses, { email: email, exp: Date.now() + 8 * 3600 * 1000 }); }
  function validEmail(e) { return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e); }

  function register(o) {
    var name = String(o.name || "").trim(), email = String(o.email || "").trim().toLowerCase(), pw = String(o.password || "");
    if (name.length < 2) return Promise.resolve(fail("Enter your name."));
    if (!validEmail(email)) return Promise.resolve(fail("Enter a valid email address."));
    if (pw.length < 8) return Promise.resolve(fail("Password needs at least 8 characters."));
    if (pw !== o.confirm) return Promise.resolve(fail("The two passwords do not match."));
    if (String(o.code || "").trim() !== DEV_CODE) return Promise.resolve(fail("That developer access code is wrong. Ask the owner for it."));
    var list = users();
    if (list.some(function (u) { return u.email === email; })) return Promise.resolve(fail("An account with this email already exists. Log in instead."));
    var salt = rand(16);
    return hashPw(pw, salt).then(function (h) {
      list.push({ name: name, email: email, salt: salt, hash: h, role: list.length ? "developer" : "owner", created: Date.now() });
      if (!write(K.users, list)) return fail("Could not save the account. Check that browser storage is allowed.");
      startSession(email);
      return { ok: true };
    });
  }

  function login(email, pw) {
    email = String(email || "").trim().toLowerCase();
    var lock = read(K.lock, { n: 0, until: 0 });
    if (lock.until > Date.now()) return Promise.resolve(fail("Too many wrong tries. Wait " + Math.ceil((lock.until - Date.now()) / 1000) + " seconds and try again."));
    var u = users().filter(function (x) { return x.email === email; })[0];
    function bad() {
      lock.n += 1;
      if (lock.n >= 5) { lock.n = 0; lock.until = Date.now() + 30000; }
      write(K.lock, lock);
      return fail("Email or password is wrong.");
    }
    if (!u) return hashPw(String(pw), "x").then(bad);
    return hashPw(String(pw || ""), u.salt).then(function (h) {
      if (h !== u.hash) return bad();
      write(K.lock, { n: 0, until: 0 });
      startSession(email);
      return { ok: true };
    });
  }

  function currentUser() {
    var s = read(K.ses, null);
    if (!s || s.exp < Date.now()) return null;
    var u = users().filter(function (x) { return x.email === s.email; })[0];
    return u ? { name: u.name, email: u.email, role: u.role } : null;
  }
  function logout() { drop(K.ses); }
  function listUsers() { return users().map(function (u) { return { name: u.name, email: u.email, role: u.role }; }); }
  function removeUser(email) {
    var me = currentUser();
    if (!me || me.role !== "owner" || me.email === email) return false;
    return write(K.users, users().filter(function (u) { return u.email !== email; }));
  }

  window.GH = {
    MODELS: MODELS, getInventory: getInventory, saveInventory: saveInventory, resetInventory: resetInventory,
    hasLocalEdits: hasLocalEdits, isSample: isSample, config: config, saveConfig: saveConfig, exportJs: exportJs,
    register: register, login: login, logout: logout, currentUser: currentUser, listUsers: listUsers, removeUser: removeUser
  };
})();
