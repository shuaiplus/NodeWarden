import type { GlobalDomainRule } from '../types';

const RAW_BITWARDEN_GLOBAL_DOMAIN_RULES: ReadonlyArray<readonly [number, readonly string[]]> = [
  [0, ['youtube.com', 'google.com', 'gmail.com']],
  [1, ['apple.com', 'icloud.com']],
  [2, ['ameritrade.com', 'tdameritrade.com']],
  [3, ['bankofamerica.com', 'bofa.com', 'mbna.com', 'usecfo.com']],
  [4, ['sprint.com', 'sprintpcs.com', 'nextel.com']],
  [5, ['wellsfargo.com', 'wf.com', 'wellsfargoadvisors.com']],
  [6, ['mymerrill.com', 'ml.com', 'merrilledge.com']],
  [7, ['accountonline.com', 'citi.com', 'citibank.com', 'citicards.com', 'citibankonline.com']],
  [8, ['cnet.com', 'cnettv.com', 'com.com', 'download.com', 'news.com', 'search.com', 'upload.com']],
  [9, ['bananarepublic.com', 'gap.com', 'oldnavy.com', 'piperlime.com']],
  [10, ['bing.com', 'hotmail.com', 'live.com', 'microsoft.com', 'msn.com', 'passport.net', 'windows.com', 'microsoftonline.com', 'office.com', 'office365.com', 'microsoftstore.com', 'xbox.com', 'azure.com', 'windowsazure.com', 'cloud.microsoft']],
  [11, ['ua2go.com', 'ual.com', 'united.com', 'unitedwifi.com']],
  [12, ['overture.com', 'yahoo.com']],
  [13, ['zonealarm.com', 'zonelabs.com']],
  [14, ['paypal.com', 'paypal-search.com']],
  [15, ['avon.com', 'youravon.com']],
  [16, ['diapers.com', 'soap.com', 'wag.com', 'yoyo.com', 'beautybar.com', 'casa.com', 'afterschool.com', 'vine.com', 'bookworm.com', 'look.com', 'vinemarket.com']],
  [17, ['1800contacts.com', '800contacts.com']],
  [18, ['amazon.com', 'amazon.com.be', 'amazon.ae', 'amazon.ca', 'amazon.co.uk', 'amazon.com.au', 'amazon.com.br', 'amazon.com.mx', 'amazon.com.tr', 'amazon.de', 'amazon.es', 'amazon.fr', 'amazon.in', 'amazon.it', 'amazon.nl', 'amazon.pl', 'amazon.sa', 'amazon.se', 'amazon.sg']],
  [19, ['cox.com', 'cox.net', 'coxbusiness.com']],
  [20, ['mynortonaccount.com', 'norton.com']],
  [21, ['verizon.com', 'verizon.net']],
  [22, ['rakuten.com', 'buy.com']],
  [23, ['siriusxm.com', 'sirius.com']],
  [24, ['ea.com', 'origin.com', 'play4free.com', 'tiberiumalliance.com']],
  [25, ['37signals.com', 'basecamp.com', 'basecamphq.com', 'highrisehq.com']],
  [26, ['steampowered.com', 'steamcommunity.com', 'steamgames.com']],
  [27, ['chart.io', 'chartio.com']],
  [28, ['gotomeeting.com', 'citrixonline.com']],
  [29, ['gogoair.com', 'gogoinflight.com']],
  [30, ['mysql.com', 'oracle.com']],
  [31, ['discover.com', 'discovercard.com']],
  [32, ['dcu.org', 'dcu-online.org']],
  [33, ['healthcare.gov', 'cuidadodesalud.gov', 'cms.gov']],
  [34, ['pepco.com', 'pepcoholdings.com']],
  [35, ['century21.com', '21online.com']],
  [36, ['comcast.com', 'comcast.net', 'xfinity.com']],
  [37, ['cricketwireless.com', 'aiowireless.com']],
  [38, ['mandtbank.com', 'mtb.com']],
  [39, ['dropbox.com', 'getdropbox.com']],
  [40, ['snapfish.com', 'snapfish.ca']],
  [41, ['alibaba.com', 'aliexpress.com', 'aliyun.com', 'net.cn']],
  [42, ['playstation.com', 'sonyentertainmentnetwork.com']],
  [43, ['mercadolivre.com', 'mercadolivre.com.br', 'mercadolibre.com', 'mercadolibre.com.ar', 'mercadolibre.com.mx']],
  [44, ['zendesk.com', 'zopim.com']],
  [45, ['autodesk.com', 'tinkercad.com']],
  [46, ['railnation.ru', 'railnation.de', 'rail-nation.com', 'railnation.gr', 'railnation.us', 'trucknation.de', 'traviangames.com']],
  [47, ['wpcu.coop', 'wpcuonline.com']],
  [48, ['mathletics.com', 'mathletics.com.au', 'mathletics.co.uk']],
  [49, ['discountbank.co.il', 'telebank.co.il']],
  [50, ['mi.com', 'xiaomi.com']],
  [51, ['facebook.com', 'messenger.com']],
  [52, ['postepay.it', 'poste.it']],
  [53, ['skysports.com', 'skybet.com', 'skyvegas.com']],
  [54, ['disneymoviesanywhere.com', 'go.com', 'disney.com', 'dadt.com', 'disneyplus.com']],
  [55, ['pokemon-gl.com', 'pokemon.com']],
  [56, ['myuv.com', 'uvvu.com']],
  [57, ['bank-yahav.co.il', 'bankhapoalim.co.il']],
  [58, ['mdsol.com', 'imedidata.com']],
  [59, ['sears.com', 'shld.net']],
  [60, ['xiami.com', 'alipay.com']],
  [61, ['belkin.com', 'seedonk.com']],
  [62, ['turbotax.com', 'intuit.com']],
  [63, ['shopify.com', 'myshopify.com']],
  [64, ['ebay.com', 'ebay.at', 'ebay.be', 'ebay.ca', 'ebay.ch', 'ebay.cn', 'ebay.co.jp', 'ebay.co.th', 'ebay.co.uk', 'ebay.com.au', 'ebay.com.hk', 'ebay.com.my', 'ebay.com.sg', 'ebay.com.tw', 'ebay.de', 'ebay.es', 'ebay.fr', 'ebay.ie', 'ebay.in', 'ebay.it', 'ebay.nl', 'ebay.ph', 'ebay.pl']],
  [65, ['techdata.com', 'techdata.ch']],
  [66, ['schwab.com', 'schwabplan.com']],
  [68, ['tesla.com', 'teslamotors.com']],
  [69, ['morganstanley.com', 'morganstanleyclientserv.com', 'stockplanconnect.com', 'ms.com']],
  [70, ['taxact.com', 'taxactonline.com']],
  [71, ['mediawiki.org', 'wikibooks.org', 'wikidata.org', 'wikimedia.org', 'wikinews.org', 'wikipedia.org', 'wikiquote.org', 'wikisource.org', 'wikiversity.org', 'wikivoyage.org', 'wiktionary.org']],
  [72, ['airbnb.at', 'airbnb.be', 'airbnb.ca', 'airbnb.ch', 'airbnb.cl', 'airbnb.co.cr', 'airbnb.co.id', 'airbnb.co.in', 'airbnb.co.kr', 'airbnb.co.nz', 'airbnb.co.uk', 'airbnb.co.ve', 'airbnb.com', 'airbnb.com.ar', 'airbnb.com.au', 'airbnb.com.bo', 'airbnb.com.br', 'airbnb.com.bz', 'airbnb.com.co', 'airbnb.com.ec', 'airbnb.com.gt', 'airbnb.com.hk', 'airbnb.com.hn', 'airbnb.com.mt', 'airbnb.com.my', 'airbnb.com.ni', 'airbnb.com.pa', 'airbnb.com.pe', 'airbnb.com.py', 'airbnb.com.sg', 'airbnb.com.sv', 'airbnb.com.tr', 'airbnb.com.tw', 'airbnb.cz', 'airbnb.de', 'airbnb.dk', 'airbnb.es', 'airbnb.fi', 'airbnb.fr', 'airbnb.gr', 'airbnb.gy', 'airbnb.hu', 'airbnb.ie', 'airbnb.is', 'airbnb.it', 'airbnb.jp', 'airbnb.mx', 'airbnb.nl', 'airbnb.no', 'airbnb.pl', 'airbnb.pt', 'airbnb.ru', 'airbnb.se']],
  [73, ['eventbrite.at', 'eventbrite.be', 'eventbrite.ca', 'eventbrite.ch', 'eventbrite.cl', 'eventbrite.co', 'eventbrite.co.nz', 'eventbrite.co.uk', 'eventbrite.com', 'eventbrite.com.ar', 'eventbrite.com.au', 'eventbrite.com.br', 'eventbrite.com.mx', 'eventbrite.com.pe', 'eventbrite.de', 'eventbrite.dk', 'eventbrite.es', 'eventbrite.fi', 'eventbrite.fr', 'eventbrite.hk', 'eventbrite.ie', 'eventbrite.it', 'eventbrite.nl', 'eventbrite.pt', 'eventbrite.se', 'eventbrite.sg']],
  [74, ['stackexchange.com', 'superuser.com', 'stackoverflow.com', 'serverfault.com', 'mathoverflow.net', 'askubuntu.com', 'stackapps.com']],
  [75, ['docusign.com', 'docusign.net']],
  [76, ['envato.com', 'themeforest.net', 'codecanyon.net', 'videohive.net', 'audiojungle.net', 'graphicriver.net', 'photodune.net', '3docean.net']],
  [77, ['x10hosting.com', 'x10premium.com']],
  [78, ['dnsomatic.com', 'opendns.com', 'umbrella.com']],
  [79, ['cagreatamerica.com', 'canadaswonderland.com', 'carowinds.com', 'cedarfair.com', 'cedarpoint.com', 'dorneypark.com', 'kingsdominion.com', 'knotts.com', 'miadventure.com', 'schlitterbahn.com', 'valleyfair.com', 'visitkingsisland.com', 'worldsoffun.com']],
  [80, ['ubnt.com', 'ui.com']],
  [81, ['discordapp.com', 'discord.com']],
  [82, ['netcup.de', 'netcup.eu', 'customercontrolpanel.de']],
  [83, ['yandex.com', 'ya.ru', 'yandex.az', 'yandex.by', 'yandex.co.il', 'yandex.com.am', 'yandex.com.ge', 'yandex.com.tr', 'yandex.ee', 'yandex.fi', 'yandex.fr', 'yandex.kg', 'yandex.kz', 'yandex.lt', 'yandex.lv', 'yandex.md', 'yandex.pl', 'yandex.ru', 'yandex.tj', 'yandex.tm', 'yandex.ua', 'yandex.uz']],
  [84, ['sonyentertainmentnetwork.com', 'sony.com']],
  [85, ['proton.me', 'protonmail.com', 'protonvpn.com']],
  [86, ['ubisoft.com', 'ubi.com']],
  [87, ['transferwise.com', 'wise.com']],
  [88, ['takeaway.com', 'just-eat.dk', 'just-eat.no', 'just-eat.fr', 'just-eat.ch', 'lieferando.de', 'lieferando.at', 'thuisbezorgd.nl', 'pyszne.pl']],
  [89, ['atlassian.com', 'bitbucket.org', 'trello.com', 'statuspage.io', 'atlassian.net', 'jira.com']],
  [90, ['pinterest.com', 'pinterest.com.au', 'pinterest.cl', 'pinterest.de', 'pinterest.dk', 'pinterest.es', 'pinterest.fr', 'pinterest.co.uk', 'pinterest.jp', 'pinterest.co.kr', 'pinterest.nz', 'pinterest.pt', 'pinterest.se']],
  [91, ['twitter.com', 'x.com']],
];

export const BITWARDEN_GLOBAL_DOMAIN_RULE_TYPES = new Set(
  RAW_BITWARDEN_GLOBAL_DOMAIN_RULES.map(([type]) => type)
);

export function cloneBitwardenGlobalDomainRules(
  excludedTypes: Iterable<number> = [],
  includeExcluded: boolean = true
): GlobalDomainRule[] {
  const excluded = new Set<number>(excludedTypes);
  const rules: GlobalDomainRule[] = [];

  for (const [type, rawDomains] of RAW_BITWARDEN_GLOBAL_DOMAIN_RULES) {
    const isExcluded = excluded.has(type);
    if (!includeExcluded && isExcluded) continue;
    const domains = [...rawDomains];
    rules.push({
      type,
      domains,
      excluded: isExcluded,
      Type: type,
      Domains: [...domains],
      Excluded: isExcluded,
    });
  }

  return rules;
}
