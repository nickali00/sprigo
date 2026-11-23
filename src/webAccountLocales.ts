import type { i18n as I18n } from "i18next";

/** Optional account UI strings, loaded only by the browser edition. */
export function installWebAccountLocales(i18n: I18n) {
  const files = import.meta.glob<{ default: Record<string, string> }>("../deploy/web/locales/*.json", { eager: true });
  for (const [path, file] of Object.entries(files)) {
    const lang = path.match(/\/([a-z-]+)\.json$/)?.[1];
    if (lang) i18n.addResourceBundle(lang, "translation", { webAccount: file.default }, true, true);
  }
}
