import * as cspell from '@iden3/eslint-config/cspell.js';
import { FlatCompat } from '@eslint/eslintrc';
import js from '@eslint/js';
import path from 'path';
import { fileURLToPath } from 'url';

// mimic CommonJS variables -- not needed if using CommonJS
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const compat = new FlatCompat({
  baseDirectory: __dirname,
  recommendedConfig: js.configs.recommended
});

export default [
  // Use FlatCompat to translate the old eslintrc config
  ...compat.config({
    parser: '@typescript-eslint/parser',
    plugins: ['@typescript-eslint', 'prettier', '@cspell/eslint-plugin'],
    extends: [
      'eslint:recommended',
      'plugin:@typescript-eslint/eslint-recommended',
      'plugin:@typescript-eslint/recommended',
      'prettier'
    ],
    rules: {
      'no-console': 1,
      'prettier/prettier': 2,
      '@cspell/spellchecker': [
        1,
        {
          ...cspell.spellcheckerRule,
          cspell: {
            ...cspell.cspellConfig,
            ignoreWords: [
              'Unmarshalled',
              'unmarshal',
              'JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw',
              'gdwj',
              'fwor',
              'multichain',
              'ETHWEI',
              'ETHGWEI',
              'didcomm',
              'pthid',
              'snarkjs',
              'ffjavascript',
              'solana',
              'lamports',
              'blockhash',
              'devnet',
              'Keypair',
              'SPLV',
              'EtWTRABZaYq6iMfeYKouRu166VU2xqa1',
              '4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z',
              '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp',
              'Rica',
              'issurance'
            ]
          }
        }
      ]
    }
  })
];
