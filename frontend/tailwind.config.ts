/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
    './src/lib/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        brand: {
          50: '#eef4ff',
          100: '#dbe6ff',
          200: '#bcd0ff',
          300: '#8eb1ff',
          400: '#5b87fb',
          500: '#3461f1',
          600: '#2347d6',
          700: '#1d3aae',
          800: '#1c328a',
          900: '#1c2e6f',
          950: '#141e47',
        },
        navy: {
          700: '#1e3050',
          800: '#1a2744',
          900: '#162036',
          950: '#0f1724',
        },
      },
    },
  },
  plugins: [],
};
