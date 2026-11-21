/**
 * The OAuth consent screen.
 *
 * Supabase's OAuth 2.1 server does not host this - it redirects here with
 * ?authorization_id=... and expects a page that asks the user whether a named
 * client may act on their behalf, then approves or denies. It is what makes
 * `claude mcp add --transport http cvefeed <url>` work without an API key.
 *
 * No third-party script. The three calls it needs are plain REST:
 *
 *   POST {auth}/otp                                   send a magic link
 *   GET  {auth}/oauth/authorizations/{id}             what is being asked for
 *   POST {auth}/oauth/authorizations/{id}/consent     { action: approve|deny }
 *
 * taken from @supabase/auth-js rather than guessed at. Keeping supabase-js off
 * this page means no CDN in the request path of an authorization decision.
 *
 * The client name and redirect URI are ATTACKER-CONTROLLED. Dynamic client
 * registration is enabled, so anyone may register a client and choose what it
 * calls itself. Every value from the API therefore reaches the page through
 * textContent and never innerHTML - the same rule the advisory text follows
 * elsewhere in this codebase, for the same reason.
 */
import { layout } from './layout.js';

export function oauthConsentPage({ canonical, assetVersion, supabaseUrl, publishableKey, allowSignup }) {
  const configured = Boolean(supabaseUrl && publishableKey);

  const body = `<article class="doc">
    <nav class="crumbs"><a href="/">Feed</a> <span>/</span> <span>Authorize</span></nav>
    <h1>Authorize an application</h1>

    ${
      configured
        ? `<p class="lede">An application is asking to use CVE Feed on your behalf. Check what it is
           and what it wants before you allow it.</p>

        <div id="oc-signin" hidden>
          <p>Sign in to continue. No password, and nothing to fill in.</p>
          <button type="button" id="oc-github" class="poc-btn primary">Continue with GitHub</button>
          <p class="oc-or">Already have an account by email? Sign in with a link instead.</p>
          <div class="mod-auth">
            <label for="oc-email">Email</label>
            <input id="oc-email" type="email" autocomplete="email" inputmode="email" placeholder="you@example.com">
            <button type="button" id="oc-send" class="poc-btn">Email me a link</button>
          </div>
        </div>

        <div id="oc-request" hidden>
          <dl class="oc-facts">
            <dt>Application</dt><dd id="oc-client">&mdash;</dd>
            <dt>Will send you back to</dt><dd id="oc-redirect">&mdash;</dd>
            <dt>Requesting</dt><dd id="oc-scopes">&mdash;</dd>
          </dl>
          <details class="oc-raw">
            <summary>Exactly what the server said</summary>
            <pre id="oc-payload"></pre>
          </details>
          <div class="mod-auth">
            <button type="button" id="oc-approve" class="poc-btn">Allow</button>
            <button type="button" id="oc-deny" class="poc-btn">Deny</button>
          </div>
          <p class="oc-note">Allowing lets this application read vulnerability data as you, within
             your rate limit. You can revoke it later, and denying sends it away with nothing.</p>
        </div>

        <p class="mod-status" id="oc-status" role="status"></p>`
        : `<p class="lede">This page is not configured. Set <code>SUPABASE_URL</code> and
           <code>SUPABASE_PUBLISHABLE_KEY</code> in the environment to enable the OAuth
           consent flow.</p>`
    }
  </article>

  ${
    configured
      ? `<script>
  (function () {
    var AUTH = ${JSON.stringify(`${supabaseUrl}/auth/v1`)};
    var KEY = ${JSON.stringify(publishableKey)};
    var ALLOW_SIGNUP = ${allowSignup ? 'true' : 'false'};
    var SESSION_KEY = 'cvefeed.sb.token';

    var el = function (id) { return document.getElementById(id); };
    var status = el('oc-status');
    var say = function (message) { if (status) status.textContent = message || ''; };
    /* Every value below originates with a client anyone may register, so it is
       written as text and never parsed as markup. */
    var put = function (id, value) { var node = el(id); if (node) node.textContent = value; };

    var params = new URLSearchParams(window.location.search);
    var authorizationId = params.get('authorization_id') || '';

    /* The magic link returns the session in the fragment. Take it, keep it for
       this tab only, and strip it from the address bar so it is not left in
       history or sent in a Referer. */
    function claimTokenFromHash() {
      if (!window.location.hash) return null;
      var hash = new URLSearchParams(window.location.hash.slice(1));
      var token = hash.get('access_token');
      if (!token) return null;
      try { sessionStorage.setItem(SESSION_KEY, token); } catch (e) { /* private mode */ }
      history.replaceState(null, '', window.location.pathname + window.location.search);
      return token;
    }

    function token() {
      try { return sessionStorage.getItem(SESSION_KEY); } catch (e) { return null; }
    }

    function headers(extra) {
      var base = { apikey: KEY, Authorization: 'Bearer ' + token() };
      if (extra) Object.keys(extra).forEach(function (k) { base[k] = extra[k]; });
      return base;
    }

    /* A full-page redirect, not a fetch: the provider dance has to happen in
       the address bar. It returns to this same URL with the session in the
       fragment, which claimTokenFromHash already knows what to do with. */
    function signInWithGitHub() {
      var back = window.location.origin + window.location.pathname +
        '?authorization_id=' + encodeURIComponent(authorizationId);
      window.location.assign(AUTH + '/authorize?provider=github&redirect_to=' + encodeURIComponent(back));
    }

    function sendLink() {
      var email = (el('oc-email').value || '').trim();
      if (!email) { say('Enter your email address first.'); return; }
      el('oc-send').disabled = true;
      say('Sending...');
      /* redirect_to carries authorization_id back, so the link returns to this
         same request rather than a bare consent page with nothing to consent to. */
      var back = window.location.origin + window.location.pathname + '?authorization_id=' + encodeURIComponent(authorizationId);
      fetch(AUTH + '/otp?redirect_to=' + encodeURIComponent(back), {
        method: 'POST',
        headers: { apikey: KEY, 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email, create_user: ALLOW_SIGNUP })
      }).then(function (response) {
        el('oc-send').disabled = false;
        if (!response.ok) {
          return response.json().catch(function () { return {}; }).then(function (payload) {
            say(payload.msg || payload.error_description || 'That did not work. Check the address and try again.');
          });
        }
        say('Check your email for a link, then come back here.');
      }).catch(function () {
        el('oc-send').disabled = false;
        say('Could not reach the sign-in service.');
      });
    }

    function scopeList(details) {
      var raw = details.scope || details.scopes || '';
      var parts = Array.isArray(raw) ? raw : String(raw).split(' ');
      parts = parts.filter(function (s) { return s; });
      return parts.length ? parts.join(', ') : 'no scopes named';
    }

    function clientName(details) {
      var client = details.client || details.oauth_client || {};
      return client.client_name || client.name || details.client_name ||
             client.client_id || 'an application that did not give a name';
    }

    function redirectTarget(details) {
      var client = details.client || details.oauth_client || {};
      return details.redirect_uri || client.redirect_uri ||
             (Array.isArray(client.redirect_uris) ? client.redirect_uris[0] : '') || 'not stated';
    }

    function decide(action) {
      el('oc-approve').disabled = true;
      el('oc-deny').disabled = true;
      say(action === 'approve' ? 'Authorizing...' : 'Denying...');
      fetch(AUTH + '/oauth/authorizations/' + encodeURIComponent(authorizationId) + '/consent', {
        method: 'POST',
        headers: headers({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ action: action })
      }).then(function (response) {
        return response.json().catch(function () { return {}; }).then(function (payload) {
          if (response.ok && payload.redirect_url) {
            window.location.assign(payload.redirect_url);
            return;
          }
          el('oc-approve').disabled = false;
          el('oc-deny').disabled = false;
          say(payload.msg || 'The server did not accept that. Start the flow again from your client.');
        });
      }).catch(function () {
        el('oc-approve').disabled = false;
        el('oc-deny').disabled = false;
        say('Could not reach the authorization server.');
      });
    }

    function loadRequest() {
      say('Loading the request...');
      fetch(AUTH + '/oauth/authorizations/' + encodeURIComponent(authorizationId), { headers: headers() })
        .then(function (response) {
          if (response.status === 401) {
            try { sessionStorage.removeItem(SESSION_KEY); } catch (e) { /* ignore */ }
            el('oc-signin').hidden = false;
            say('That sign-in has expired. Request a new link.');
            return null;
          }
          return response.json().catch(function () { return {}; }).then(function (payload) {
            if (!response.ok) { say(payload.msg || 'The authorization request could not be read.'); return null; }
            return payload;
          });
        })
        .then(function (details) {
          if (!details) return;
          /* Only a redirect_url means consent was already given for this client. */
          if (details.redirect_url && !details.client && !details.scope && !details.scopes) {
            window.location.assign(details.redirect_url);
            return;
          }
          put('oc-client', clientName(details));
          put('oc-redirect', redirectTarget(details));
          put('oc-scopes', scopeList(details));
          put('oc-payload', JSON.stringify(details, null, 2));
          el('oc-request').hidden = false;
          say('');
        })
        .catch(function () { say('Could not reach the authorization server.'); });
    }

    claimTokenFromHash();

    if (!authorizationId) {
      say('This page is the last step of an application sign-in. Start from the application and you will be sent here.');
      return;
    }
    el('oc-github').addEventListener('click', signInWithGitHub);
    el('oc-send').addEventListener('click', sendLink);
    el('oc-email').addEventListener('keydown', function (event) { if (event.key === 'Enter') sendLink(); });
    el('oc-approve').addEventListener('click', function () { decide('approve'); });
    el('oc-deny').addEventListener('click', function () { decide('deny'); });

    if (token()) loadRequest();
    else { el('oc-signin').hidden = false; say(''); }
  })();
  </script>`
      : ''
  }`;

  return layout({
    title: 'Authorize an application - CVE Feed',
    description: 'Review and approve an application asking to use CVE Feed on your behalf.',
    canonical,
    body,
    noindex: true,
    assetVersion,
  });
}

export default { oauthConsentPage };
