import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";

import { ApiError } from "@/api/client";
import { App } from "@/App";
import { I18nProvider } from "@/i18n";

import "./styles.css";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: (failureCount, error) => {
        // Bei 401/403 nicht wiederholen – der Nutzer muss sich anmelden.
        if (error instanceof ApiError && [401, 403].includes(error.status)) return false;
        return failureCount < 2;
      },
    },
  },
});

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <I18nProvider>
        {/* Der Basispfad stammt aus <base href>, das das Backend auf
            FRM_ROOT_PATH setzt – sonst greift unter einem Präfix keine Route. */}
        <BrowserRouter basename={new URL(document.baseURI).pathname}>
          <App />
        </BrowserRouter>
      </I18nProvider>
    </QueryClientProvider>
  </StrictMode>,
);
