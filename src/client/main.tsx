/** Browser entry point for the control-plane portal application. */

import React from "react";
import ReactDOM from "react-dom/client";

import { App } from "./app";
import "./styles.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
