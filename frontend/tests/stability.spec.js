import { test, expect } from '@playwright/test'
import fs from 'node:fs'

// Supplementary isolated browser checks; these do not claim access to the
// user's Chrome/OS clipboard or export its network traffic.
test('clipboard success writes exact public contract root and transaction values', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write'])
  await page.goto('/blockchain-audit')
  const contract = page.locator('.audit-network').getByRole('button', { name: /^Copy / }).first()
  const batch = page.locator('tbody tr').first()
  await expect(batch).toContainText('ANCHORED')
  const buttons = [contract, batch.getByRole('button', { name: /^Copy / }).nth(0), batch.getByRole('button', { name: /^Copy / }).nth(1)]
  for (const button of buttons) {
    const value = (await button.getAttribute('aria-label')).slice(5)
    expect(value).toMatch(/^0x[0-9a-fA-F]+$/)
    await button.click()
    await expect(button).toHaveAttribute('title', 'Copied')
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(value)
  }
})

test('network journeys use local API websocket and genuine audit proofs', async ({ page }) => {
  const requests = [], failures = [], sockets = [], errors = []
  // Whitelist metadata only: never collect bodies, headers, query strings,
  // authentication envelopes, signatures or WebSocket payloads.
  page.on('response', response => {
    const url = new URL(response.url())
    if (['http://127.0.0.1:8001', 'http://127.0.0.1:8002'].includes(url.origin)) requests.push({ origin: url.origin, method: response.request().method(), path: url.pathname, status: response.status() })
  })
  page.on('requestfailed', request => {
    const url = new URL(request.url())
    failures.push({ path: url.pathname, error: request.failure()?.errorText })
  })
  page.on('pageerror', error => errors.push(error.name))
  page.on('websocket', socket => {
    const url = new URL(socket.url())
    const entry = { origin: url.origin, path: url.pathname, eventTypes: [] }
    sockets.push(entry)
    socket.on('framereceived', frame => {
      try { const data = JSON.parse(String(frame.payload)); if (typeof data.event === 'string') entry.eventTypes.push(data.event) } catch { /* Recorded by UI assertions if the response cannot be parsed. */ }
    })
  })
  await page.goto('/governance')
  await page.getByRole('button', { name: 'Normal action', exact: true }).click()
  await expect(page.locator('.verdict-visual h2')).toHaveText('ALLOW')
  await page.getByRole('link', { name: 'Blockchain Audit', exact: true }).click()
  await page.getByRole('combobox', { name: 'Action ID' }).selectOption({ index: 1 })
  await expect(page.locator('.audit-record-summary')).toContainText('VERIFIED')
  await page.getByRole('button', { name: 'Test tamper detection', exact: true }).click()
  await expect(page.locator('.audit-record-summary')).toContainText('TAMPERED')
  await page.getByRole('button', { name: 'Refresh', exact: true }).click()
  await expect(page.locator('tbody tr').first()).toContainText('ANCHORED')
  await page.reload()
  await expect(page.locator('tbody tr').first()).toContainText('ANCHORED')
  const result = { surface: 'supplementary isolated Edge; NOT connected Chrome HAR', requests, failures, sockets, errors }
  fs.writeFileSync('../.runtime/stability-network.json', JSON.stringify(result, null, 2))
  expect(requests.length).toBeGreaterThan(0)
  expect(requests.filter(row => row.status >= 400)).toEqual([])
  expect(failures.filter(row => !row.error?.includes('ERR_ABORTED'))).toEqual([])
  expect(errors).toEqual([])
  const apiOrigins = new Set(requests.map(request => request.origin.replace('http:', 'ws:')))
  expect(sockets.some(socket => apiOrigins.has(socket.origin) && socket.eventTypes.includes('VERDICT_COMPLETE'))).toBe(true)
})
