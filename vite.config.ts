/** Builds the React customer and owner portals as static Worker assets. */

import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
});
