/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./src/**/*.{js,jsx,ts,tsx}"],
  theme: {
    extend: {
      colors: {
        navy: {
          950: "#060D17",
          900: "#0C1929",
          800: "#112236",
          700: "#173049",
          600: "#1D3F5E",
          500: "#254E74",
          400: "#3A6A94",
        },
        brand: {
          DEFAULT: "#EB5F28",
          light: "#F97316",
          dark: "#C44A1A",
        },
      },
      fontFamily: {
        sans: ['"Inter"', '"Segoe UI"', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', '"Fira Code"', 'monospace'],
      },
    },
  },
  plugins: [],
};
