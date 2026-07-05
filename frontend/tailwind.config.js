/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        base: {
          900: "#0a0c12",
          800: "#0f1218",
          750: "#141821",
          700: "#1a1f2b",
          600: "#232a38",
          500: "#2e3646",
        },
        ink: {
          50: "#f4f6fb",
          100: "#dfe4ee",
          200: "#b7c0d4",
          300: "#8b96b0",
          400: "#5f6b86",
        },
        accent: {
          cyan: "#22d3ee",
          blue: "#3b82f6",
          violet: "#8b5cf6",
        },
        sev: {
          critical: "#ef4444",
          high: "#f97316",
          medium: "#eab308",
          low: "#3b82f6",
          info: "#64748b",
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "monospace"],
      },
      boxShadow: {
        glow: "0 0 24px -4px rgba(34, 211, 238, 0.35)",
      },
    },
  },
  plugins: [],
};
