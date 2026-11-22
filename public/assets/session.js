/*
 * One sign-in, shared by every page that needs it.
 *
 * GitHub is the only way in. Supabase sends the browser back with the session
 * in the URL fragment; this takes it, keeps it for this tab only, and strips
 * it from the address bar so it is not left in history or sent in a Referer.
 *
 * sessionStorage rather than localStorage: closing the tab signs you out of
 * this page, which is the right default for an account that can mint API keys.
 *
 * The page supplies its Supabase Auth URL in <meta name="cvefeed-auth">. The
 * publishable key is not needed here - /authorize takes none.
 */
(function () {
  var KEY = 'cvefeed.sb.token';
  var meta = document.querySelector('meta[name="cvefeed-auth"]');
  var AUTH = meta ? meta.getAttribute('content') : '';

  function read() {
    try { return JSON.parse(sessionStorage.getItem(KEY) || 'null'); } catch (e) { return null; }
  }
  function write(value) {
    try {
      if (value) sessionStorage.setItem(KEY, JSON.stringify(value));
      else sessionStorage.removeItem(KEY);
    } catch (e) { /* private mode: signed in for this page load only */ }
  }

  (function claim() {
    if (!window.location.hash) return;
    var hash = new URLSearchParams(window.location.hash.slice(1));
    var token = hash.get('access_token');
    if (!token) return;
    var expiresIn = Number(hash.get('expires_in') || 3600);
    write({ token: token, expiresAt: Date.now() + expiresIn * 1000 });
    history.replaceState(null, '', window.location.pathname + window.location.search);
  })();

  /* Only same-site paths: a ?next= naming another origin would make this an
     open redirect, a phisher's favourite tool. */
  function safeNext(next) {
    return typeof next === 'string' && next.charAt(0) === '/' && next.charAt(1) !== '/' ? next : '/mcp';
  }

  window.CvefeedSession = {
    getToken: function () {
      var s = read();
      if (!s || !s.token) return null;
      // A minute's grace so a request does not set off with a token that dies
      // in flight. Expired means sign in again; there is no silent refresh.
      if (s.expiresAt && Date.now() > s.expiresAt - 60000) { write(null); return null; }
      return s.token;
    },
    signIn: function (next) {
      if (!AUTH) return;
      var back = window.location.origin + safeNext(next || window.location.pathname + window.location.search);
      window.location.assign(AUTH + '/authorize?provider=github&redirect_to=' + encodeURIComponent(back));
    },
    signOut: function () { write(null); },
    safeNext: safeNext,
  };
})();
