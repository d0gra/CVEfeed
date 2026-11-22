/**
 * /signin - GitHub, and nothing else.
 *
 * The email magic link is gone: Supabase's built-in mail is capped at 30 an
 * hour and can only reach the organisation's own addresses, so it could never
 * have served the public. GitHub needs no SMTP, and for a tool that serves
 * exploit intelligence a verified developer identity is the better account.
 *
 * ?next= says where to go afterwards, restricted to this site's own paths by
 * session.js so the page cannot be used as an open redirect.
 */
import { escapeHtml, layout } from './layout.js';
import { brandIcon } from './brandIcons.js';

/** The two tags every signed-in page needs. */
export const sessionHead = (supabaseUrl, assetVersion = '') =>
  `<meta name="cvefeed-auth" content="${escapeHtml(`${supabaseUrl}/auth/v1`)}">` +
  `<script src="/assets/session.js${assetVersion ? `?v=${encodeURIComponent(assetVersion)}` : ''}"></script>`;

export function signinPage({ canonical, assetVersion, supabaseUrl }) {
  const configured = Boolean(supabaseUrl);
  const body = `<article class="doc signin-page">
    <h1>Sign in to CVE Feed</h1>
    ${
      configured
        ? `<p class="lede">One click with your GitHub account. New accounts can make 60 MCP calls an
           hour, and you can see exactly what you've used once you're in.</p>
        <button type="button" id="signin-github" class="install-btn signin-btn">
          ${brandIcon('github')}<span>Continue with GitHub</span>
        </button>
        <p class="aside">We read your GitHub profile and email to identify your account, and
           nothing else. No password is stored here.</p>
        ${sessionHead(supabaseUrl, assetVersion)}
        <script>
        (function () {
          var next = new URLSearchParams(window.location.search).get('next');
          var target = window.CvefeedSession.safeNext(next);
          /* Already signed in, or just arrived back from GitHub: go on. */
          if (window.CvefeedSession.getToken()) { window.location.replace(target); return; }
          document.getElementById('signin-github').addEventListener('click', function () {
            window.CvefeedSession.signIn(target);
          });
        })();
        </script>`
        : `<p class="lede">Sign-in is not configured on this host.</p>`
    }
  </article>`;

  return layout({
    title: 'Sign in | CVE Feed',
    description: 'Sign in to CVE Feed with GitHub to connect an AI agent over MCP.',
    canonical,
    body,
    noindex: true,
    assetVersion,
  });
}

export default { signinPage, sessionHead };
