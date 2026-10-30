import config from '../config.js';
import nvd from './nvd.js';
import kev from './kev.js';
import github from './github.js';
import euvd from './euvd.js';
import cisa from './cisa.js';

export const ALL_SOURCES = [nvd, kev, github, euvd, cisa];

export const SOURCE_BY_ID = Object.fromEntries(ALL_SOURCES.map((s) => [s.meta.id, s]));

/** Sources enabled by configuration, in a stable display order. */
export function enabledSources() {
  const enabled = ALL_SOURCES.filter((s) => config.sources.includes(s.meta.id));
  return enabled.length > 0 ? enabled : ALL_SOURCES;
}

export default { ALL_SOURCES, SOURCE_BY_ID, enabledSources };
