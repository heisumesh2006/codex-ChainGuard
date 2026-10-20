import { test, expect } from '@playwright/test'

async function selectOriginal(page) {
  await page.goto('/blockchain-audit')
  const response = page.waitForResponse(r => r.url().includes('/proof') && r.status() === 200)
  await page.getByRole('combobox', { name: 'Action ID' }).selectOption({ index: 1 })
  const proof = await (await response).json()
  await expect(page.locator('.audit-record-summary')).toContainText('VERIFIED')
  return proof
}

test('audit clarity original copy comparison and restoration use real verification', async ({ page }) => {
  const original = await selectOriginal(page)
  let posts = 0
  page.on('request', request => { if (request.method() === 'POST' && request.url().endsWith('/verify')) posts++ })
  const candidateResponse = page.waitForResponse(response => response.url().endsWith('/verify') && response.request().postDataJSON()?.record_override)
  await page.getByRole('button', { name: 'Simulate Tampering', exact: true }).dblclick()
  const modified = await (await candidateResponse).json()
  const copy = page.getByRole('region', { name: 'Simulated modified copy' })
  await expect(copy).toContainText('TAMPERING DETECTED')
  expect(posts).toBe(2) // One original check and one candidate check, not duplicate simulations.
  await expect(page.locator('.audit-record-summary')).toContainText('ORIGINAL STORED RECORD')
  await expect(page.locator('.audit-record-summary')).toContainText('VERIFIED')
  await expect(copy).toContainText(JSON.stringify(original.record.target ?? null))
  await expect(copy).toContainText(`${original.record.target || 'audit-record'} [tampered demo copy]`)
  const originalHash = page.locator('.audit-record-summary').getByRole('button', { name: `Copy ${original.record_hash}`, exact: true })
  await expect(originalHash).toBeVisible()
  await expect(copy.getByRole('button', { name: `Copy ${original.blockchain_root}`, exact: true })).toBeVisible()
  expect(modified.record_hash).not.toBe(original.record_hash)
  await expect(copy.getByRole('button', { name: `Copy ${modified.record_hash}`, exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Verify Original', exact: true }).click()
  await expect(copy).toHaveCount(0)
  await expect(page.locator('.audit-record-summary')).toContainText('VERIFIED')
  await expect(originalHash).toBeVisible()
  await page.getByRole('button', { name: 'Simulate Tampering', exact: true }).click()
  await expect(copy).toContainText('TAMPERED')
  await page.getByRole('combobox', { name: 'Action ID' }).selectOption({ index: 2 })
  await expect(copy).toHaveCount(0)
  await expect(page.locator('.audit-record-summary')).toContainText('VERIFIED')
  await page.getByRole('button', { name: 'Simulate Tampering', exact: true }).click()
  await expect(copy).toContainText('TAMPERED')
  await page.getByRole('button', { name: 'Refresh', exact: true }).click()
  await expect(copy).toHaveCount(0)
  await page.reload()
  await expect(copy).toHaveCount(0)
})

test('audit clarity RPC and missing-proof errors never claim success', async ({ page }) => {
  await selectOriginal(page)
  await page.route('**/api/audit/actions/*/verify', route => route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ detail: 'RPC_UNAVAILABLE' }) }))
  await page.getByRole('button', { name: 'Simulate Tampering', exact: true }).click()
  await expect(page.locator('.error-banner')).toContainText('RPC_UNAVAILABLE')
  await expect(page.locator('.audit-simulation')).toHaveCount(0)
  await expect(page.locator('.audit-record-summary')).toHaveCount(0)
  await page.route('**/api/audit/actions/*/proof', route => route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ detail: 'PROOF_UNAVAILABLE' }) }))
  await page.getByRole('combobox', { name: 'Action ID' }).selectOption({ index: 2 })
  await expect(page.locator('.error-banner')).toContainText('PROOF_UNAVAILABLE')
  await expect(page.locator('.audit-simulation')).toHaveCount(0)
  // A successful background inventory poll must not erase a proof error.
  await page.waitForResponse(response => response.url().includes('/api/audit/status') && response.status() === 200)
  await expect(page.locator('.error-banner')).toContainText('PROOF_UNAVAILABLE')
})

test('audit clarity missing anchor and pending results are not tamper success', async ({ page }) => {
  const original = await selectOriginal(page)
  let requests = 0
  await page.route('**/api/audit/actions/*/verify', route => {
    requests++
    const result = requests % 2 ? original : { ...original, result: 'TAMPERED', record_hash: '0x' + 'ab'.repeat(32), blockchain_root: null, calculated_root: null }
    return route.fulfill({ json: result })
  })
  await page.getByRole('button', { name: 'Simulate Tampering', exact: true }).click()
  await expect(page.locator('.audit-simulation')).toContainText('SIMULATION NOT CONFIRMED')
  await expect(page.getByText('TAMPERING DETECTED', { exact: true })).toHaveCount(0)
  await page.unroute('**/api/audit/actions/*/verify')
  await page.route('**/api/audit/actions/*/verify', route => route.fulfill({ json: { ...original, result: 'PENDING', blockchain_root: null } }))
  await page.getByRole('button', { name: 'Simulate Tampering', exact: true }).click()
  await expect(page.locator('.audit-record-summary')).toContainText('PENDING')
  await expect(page.locator('.audit-simulation')).toHaveCount(0)
})

test('audit clarity late request cannot replace another selected record', async ({ page }) => {
  await selectOriginal(page)
  let release, entered
  const blocked = new Promise(resolve => { entered = resolve })
  const gate = new Promise(resolve => { release = resolve })
  await page.route('**/api/audit/actions/*/verify', async route => {
    const response = await route.fetch()
    entered()
    await gate
    await route.fulfill({ response })
  })
  await page.getByRole('button', { name: 'Simulate Tampering', exact: true }).click()
  await blocked
  const selected = page.waitForResponse(r => r.url().includes('/proof') && r.status() === 200)
  await page.getByRole('combobox', { name: 'Action ID' }).selectOption({ index: 2 })
  const next = await (await selected).json()
  release()
  await expect(page.locator('.audit-record-summary')).toContainText('VERIFIED')
  await expect(page.locator('.audit-record-summary').getByRole('button', { name: `Copy ${next.action_id}`, exact: true })).toBeVisible()
  await expect(page.locator('.audit-simulation')).toHaveCount(0)
})

test('audit clarity comparison is responsive at four requested sizes', async ({ page }) => {
  await selectOriginal(page)
  await page.getByRole('button', { name: 'Simulate Tampering', exact: true }).click()
  await expect(page.locator('.audit-simulation')).toContainText('TAMPERING DETECTED')
  for (const [width, height] of [[1920, 1080], [1366, 768], [768, 1024], [390, 844]]) {
    await page.setViewportSize({ width, height })
    await expect(page.getByRole('button', { name: 'Verify Original', exact: true })).toBeVisible()
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
  }
})
