import { defineConfig } from '@playwright/test'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const directory = path.dirname(fileURLToPath(import.meta.url))
const python = path.resolve(directory, '..', '.venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python')
export default defineConfig({
  testDir: './tests', timeout: 300000, expect: { timeout: 180000 },
  workers: 1, retries: 0, forbidOnly: true,
  outputDir: '../.runtime/browser-artifacts',
  reporter: [['list'], ['json', { outputFile: '../.runtime/browser-results.json' }]],
  use: { baseURL: 'http://127.0.0.1:5179', channel: 'msedge', viewport: { width: 1440, height: 1000 }, screenshot: 'only-on-failure' },
  webServer: [
    { command: `"${python}" -m backend.api.tests.e2e_server`, cwd: path.resolve(directory,'..'), url: 'http://127.0.0.1:8002/api/health', timeout: 120000 },
    { command: 'npm run build && npm run preview -- --host 127.0.0.1 --port 5179 --strictPort', url: 'http://127.0.0.1:5179', env: { VITE_API_BASE_URL: 'http://127.0.0.1:8002' }, timeout: 120000 },
  ],
})
