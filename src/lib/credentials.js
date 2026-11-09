/**
 * What to say when a source was fetched with no credential.
 *
 * Its own module so the wording is tested rather than only seen in a cron log
 * nobody reads. The case it exists for: a token set in a hosting panel
 * reaches the web app Passenger starts and not the cron job that does the
 * fetching, so the variable is unquestionably "set" and the requests still go
 * out anonymous - and the only symptom is a 403 that reads like an outage at
 * the other end.
 */

/**
 * @param sources the per-source health from a refresh
 * @param cwd     the directory dotenv read .env from
 * @returns lines to print, loudest first; empty when every source was authenticated
 */
export function anonymousNotes(sources = [], cwd = process.cwd()) {
  const anonymous = sources.filter((s) => s?.authenticated === false);
  if (anonymous.length === 0) return [];

  const lines = anonymous.map((source) => {
    const refused = !source.ok;
    return (
      `${refused ? 'WARNING' : 'note   '}  ${source.id} fetched anonymously: no ${source.authEnv ?? 'credential'} in this process` +
      (refused ? ' - and it was refused, which is what an exhausted anonymous budget looks like' : '')
    );
  });

  // Sort the refused ones first: with several anonymous sources, the one that
  // actually failed is the one to read.
  lines.sort((a, b) => Number(b.startsWith('WARNING')) - Number(a.startsWith('WARNING')));

  lines.push(
    `         this process reads ${cwd}/.env (dotenv reads no other file).` +
      ' A variable set only in a hosting panel reaches the web app, not cron.',
  );
  return lines;
}

export default { anonymousNotes };
