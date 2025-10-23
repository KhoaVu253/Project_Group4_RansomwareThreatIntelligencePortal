import React, { createContext, useContext, useEffect, useMemo, useState } from 'react';

const LanguageContext = createContext({
  language: 'vi',
  setLanguage: () => {},
  translate: (vi, en) => vi,
});

const LANGUAGE_STORAGE_KEY = 'vt-language';
const SUPPORTED_LANGUAGES = ['vi', 'en'];

export const LanguageProvider = ({ children }) => {
  const [language, setLanguage] = useState(() => {
    if (typeof window === 'undefined') return 'vi';
    const stored = window.localStorage.getItem(LANGUAGE_STORAGE_KEY);
    return SUPPORTED_LANGUAGES.includes(stored) ? stored : 'vi';
  });

  useEffect(() => {
    if (typeof document !== 'undefined') {
      document.documentElement.lang = language;
      window.localStorage.setItem(LANGUAGE_STORAGE_KEY, language);
    }
  }, [language]);

  const translate = (vi, en) => (language === 'vi' ? vi : en);

  const value = useMemo(
    () => ({
      language,
      setLanguage,
      translate,
    }),
    [language]
  );

  return <LanguageContext.Provider value={value}>{children}</LanguageContext.Provider>;
};

export const useLanguage = () => useContext(LanguageContext);
