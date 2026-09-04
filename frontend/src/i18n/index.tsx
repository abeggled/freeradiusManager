import { useCallback, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";

import { I18nContext, type Language, type Translate } from "./context";
import { de, type TranslationKey } from "./de";
import { en } from "./en";

const catalogs: Record<Language, Record<string, string>> = { de, en };
const STORAGE_KEY = "frm.language";

function detectLanguage(): Language {
  const stored = window.localStorage.getItem(STORAGE_KEY);
  if (stored === "de" || stored === "en") return stored;
  return navigator.language.toLowerCase().startsWith("en") ? "en" : "de";
}

/** Zweisprachigkeit von Beginn an (Spezifikation NFR-4). */
export function I18nProvider({ children }: { children: ReactNode }) {
  const [language, setLanguageState] = useState<Language>(detectLanguage);

  // Das Cookie ist sitzungsgebunden, die Auswahl steht dauerhaft im
  // localStorage. Ohne diesen Abgleich kämen Fehlermeldungen nach einem
  // Browser-Neustart in der Kontosprache, während die Oberfläche umgestellt ist.
  useEffect(() => {
    document.documentElement.lang = language;
    document.cookie = `frm_lang=${language}; path=/; SameSite=Lax`;
  }, [language]);

  const setLanguage = useCallback((next: Language) => {
    window.localStorage.setItem(STORAGE_KEY, next);
    setLanguageState(next);
  }, []);

  const t = useCallback<Translate>(
    (key, params) => {
      const template = catalogs[language][key] ?? catalogs.de[key] ?? key;
      if (!params) return template;
      return template.replace(/\{(\w+)\}/g, (match, name: string) =>
        params[name] === undefined ? match : String(params[name]),
      );
    },
    [language],
  );

  const value = useMemo(() => ({ language, setLanguage, t }), [language, setLanguage, t]);
  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

// Re-Export des Hooks: Bequemlichkeit fuer die Aufrufer. Die Regel zielt auf
// Dateien mit gemischten Definitionen; hier steht nur eine Weiterleitung.
// eslint-disable-next-line react-refresh/only-export-components
export { useI18n } from "./context";
export type { Language, Translate } from "./context";
export type { TranslationKey };
