import { defineConfig } from '@playwright/test'

// Targeted regressions for the already-running disposable Hardhat demo.
// No server lifecycle, deployment, signer service or public RPC is involved.
export default defineConfig({
  testDir: './tests', workers: 1, retries: 0, forbidOnly: true,
  grep: /audit clarity|audit original|clipboard failure|clipboard success|network journeys|paused replay|profile evidence|all graph|signed action input|unknown route/,
  timeout: 120000, expect: { timeout: 60000 },
  outputDir: '../.runtime/local-qa-browser-artifacts',
  reporter: [['list'], ['json', { outputFile: '../.runtime/live-chrome-local-browser-results.json' }]],
  use: { baseURL: 'http://localhost:5173', channel: 'msedge',
         viewport: { width: 1440, height: 1000 }, screenshot: 'only-on-failure' },
})
