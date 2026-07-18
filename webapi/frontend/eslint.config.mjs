import nextPlugin from 'eslint-config-next';

export default [
  ...nextPlugin,
  {
    ignores: ['.next/**', 'out/**', 'node_modules/**'],
  },
];
