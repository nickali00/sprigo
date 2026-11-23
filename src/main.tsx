import React from "react";
import ReactDOM from "react-dom/client";
import "@fontsource/nunito/400.css";
import "@fontsource/nunito/600.css";
import "@fontsource/nunito/700.css";
import "@fontsource/nunito/800.css";
import "@fontsource/nunito/900.css";
// Readable font option (#34); the files only load once Settings turns it on.
import "@fontsource/atkinson-hyperlegible-next/400.css";
import "@fontsource/atkinson-hyperlegible-next/600.css";
import "@fontsource/atkinson-hyperlegible-next/700.css";
import "@fontsource/atkinson-hyperlegible-next/800.css";
import "./styles.css";
import i18n from "./i18n";
import "./theme";
import { AppProvider } from "./store";
import App from "./App";
import { isCompanion, isWeb } from "./db";
import { registerOfflinePage } from "./companion";

if (isCompanion && !isWeb) registerOfflinePage();

const root = ReactDOM.createRoot(document.getElementById("root") as HTMLElement);
const app = <AppProvider><App /></AppProvider>;
if (isWeb) {
  void Promise.all([import("./WebAccess"), import("./webAccountLocales")]).then(([{ WebAccessGate }, { installWebAccountLocales }]) => {
    installWebAccountLocales(i18n);
    root.render(<React.StrictMode><WebAccessGate>{app}</WebAccessGate></React.StrictMode>);
  });
} else {
  root.render(<React.StrictMode>{app}</React.StrictMode>);
}
