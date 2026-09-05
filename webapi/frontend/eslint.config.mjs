import nextPlugin from 'eslint-config-next';

const config = [
  ...nextPlugin,
  {
    ignores: ['.next/**', 'out/**', 'node_modules/**'],
  },
];

export default config;
