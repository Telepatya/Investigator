/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        base: {
          900: "rgb(var(--base-900) / <alpha-value>)",
          800: "rgb(var(--base-800) / <alpha-value>)",
          750: "rgb(var(--base-750) / <alpha-value>)",
          700: "rgb(var(--base-700) / <alpha-value>)",
          600: "rgb(var(--base-600) / <alpha-value>)",
          500: "rgb(var(--base-500) / <alpha-value>)",
        },
        ink: {
          50: "rgb(var(--ink-50) / <alpha-value>)",
          100: "rgb(var(--ink-100) / <alpha-value>)",
          200: "rgb(var(--ink-200) / <alpha-value>)",
          300: "rgb(var(--ink-300) / <alpha-value>)",
          400: "rgb(var(--ink-400) / <alpha-value>)",
          500: "rgb(var(--ink-500) / <alpha-value>)",
          600: "rgb(var(--ink-600) / <alpha-value>)",
        },
        accent: {
          cyan: "rgb(var(--accent-cyan) / <alpha-value>)",
          blue: "rgb(var(--accent-blue) / <alpha-value>)",
          violet: "rgb(var(--accent-violet) / <alpha-value>)",
        },
        sev: {
          critical: "rgb(var(--sev-critical) / <alpha-value>)",
          high: "rgb(var(--sev-high) / <alpha-value>)",
          medium: "rgb(var(--sev-medium) / <alpha-value>)",
          low: "rgb(var(--sev-low) / <alpha-value>)",
          info: "rgb(var(--sev-info) / <alpha-value>)",
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "monospace"],
      },
      boxShadow: {
        glow: "0 14px 34px -18px rgb(var(--accent-blue) / 0.65)",
        glass: "0 22px 60px -36px rgb(45 76 132 / 0.55)",
      },
    },
  },
  plugins: [],
};
