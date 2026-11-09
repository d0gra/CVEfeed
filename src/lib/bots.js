/**
 * Is this request a crawler?
 *
 * /cve/:id answers for any CVE that exists, and the sitemap invites crawlers
 * to walk them. Each miss used to fan out to every register - so a crawler
 * working through a few hundred thousand ids generated a few hundred thousand
 * upstream requests, none of them for a reader waiting on an answer.
 *
 * A crawler gets what the store already holds. That is the whole page for
 * anything in the feed, and an honest 404 for the rest, which is also the
 * right answer to index.
 */
const BOT = /bot|crawler|spider|crawling|slurp|mediapartners|facebookexternalhit|embedly|quora link preview|showyoubot|outbrain|pinterest|vkshare|w3c_validator|whatsapp|telegram|discord|headlesschrome|python-requests|curl\/|wget\/|scrapy|go-http-client|okhttp|java\/|libwww-perl/i;

export const isBot = (userAgent) => BOT.test(String(userAgent ?? ''));

export default { isBot };
