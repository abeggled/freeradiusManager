import { createContext, useContext } from "react";

import type { TranslationKey } from "./de";

export type Language = "de" | "en";

export type Translate = (
  key: TranslationKey,
  params?: Record<string, string | number>,
) => string;

export interface I18nValue {
  language: Language;
  setLanguage: (language: Language) => void;
  t: Translate;
}

export const I18nContext = createContext<I18nValue | null>(null);

export function useI18n(): I18nValue {
  const value = useContext(I18nContext);
  if (!value) throw new Error("useI18n ausserhalb des I18nProvider verwendet");
  return value;
}
