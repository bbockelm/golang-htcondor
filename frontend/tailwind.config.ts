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
        // brand: a CHTC-red palette derived from the CHTC logo's
        // primary fill (#b61f24). The logo color lands at 600 — that's
        // the shade we use for "primary action" surfaces (buttons,
        // active links). 700+ are darker hover/pressed states; 50-200
        // are tints for hover backgrounds and subtle borders.
        //
        // The CHTC logo also uses true black (#000) as its secondary;
        // the `ink` palette below covers that side.
        brand: {
          50: '#fef2f2',
          100: '#fde2e3',
          200: '#fbc8ca',
          300: '#f6a0a4',
          400: '#ee6b71',
          500: '#de434a',
          600: '#b61f24', // CHTC red — the logo color
          700: '#971c20',
          800: '#7c1c1f',
          900: '#681c1e',
          950: '#38080a',
        },
        // ink: charcoal-to-black scale used for the sidebar and other
        // dark UI surfaces. Replaces the previous `navy` palette so
        // the chrome reads as the CHTC black-and-red theme. 950 is
        // near-true-black; 900-700 are graduated panel/hover shades.
        ink: {
          50: '#f6f6f6',
          100: '#e7e7e7',
          200: '#d1d1d1',
          300: '#b0b0b0',
          400: '#888888',
          500: '#6d6d6d',
          600: '#5d5d5d',
          700: '#3f3f3f',
          800: '#2c2c2c',
          900: '#1a1a1a',
          950: '#0a0a0a',
        },
      },
    },
  },
  plugins: [],
};
