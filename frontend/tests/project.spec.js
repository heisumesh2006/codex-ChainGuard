import { test, expect } from '@playwright/test'

const routes = [
  ['/', 'Command overview'], ['/agents', 'Agent Directory'], ['/trust-graph', 'Trust Graph'],
  ['/governance', 'Decision Pipeline'], ['/threat-lab', 'Threat Lab'], ['/analytics', 'ML Analytics'],
  ['/revocation', 'Revocation Center'], ['/evaluation', 'Evaluation'], ['/blockchain-audit', 'Blockchain Audit'],
]

test.beforeEach(async ({ page }, info) => {
  const errors = [], responses = [], runtimeErrors = []
  page.on('pageerror', error => { errors.push(error.message); runtimeErrors.push(error.message) })
  page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
  page.on('response', response => {
    if (response.url().includes('/api/')) responses.push({ path: new URL(response.url()).pathname, status: response.status() })
  })
  info.auditErrors = errors; info.auditResponses = responses; info.runtimeErrors = runtimeErrors; info.expectedApiFailures = []
})

test.afterEach(async ({ page }, info) => {
  await info.attach('console-and-api', { body: JSON.stringify({ errors: info.auditErrors, responses: info.auditResponses }), contentType: 'application/json' })
  expect(info.runtimeErrors).toEqual([])
  expect(info.auditErrors.filter(message => !info.title.includes('failure') || !message.startsWith('Failed to load resource:'))).toEqual([])
  expect(info.auditResponses.filter(item => item.status >= 500 && !(item.status === 503 && info.expectedApiFailures.includes(item.path)))).toEqual([])
})

for (const [route] of routes) {
  test(`page ${route} renders with live read-only evidence`, async ({ page }) => {
    await page.goto(route)
    await expect(page.locator('h1')).toBeVisible()
    await expect(page.locator('.topbar')).toContainText('Ethereum Sepolia')
    await expect(page.locator('.topbar')).toContainText('System Online')
    if (route === '/') await expect(page.locator('.dashboard-agent:not(.skeleton)')).toHaveCount(4)
    if (route === '/agents') await expect(page.locator('.agent-card')).toHaveCount(4)
    if (route === '/trust-graph') await expect(page.locator('.react-flow__node')).toHaveCount(5)
    if (route === '/analytics') await expect(page.locator('.analytics-scope')).toContainText('REVIEW')
    if (route === '/revocation') await expect(page.locator('section.revocation-result')).toContainText('VERIFIED ON-CHAIN')
    if (route === '/evaluation') await expect(page.locator('.evaluation-table-wrap tbody tr')).toHaveCount(5)
    if (route === '/blockchain-audit') await expect(page.locator('.audit-table tbody tr')).toHaveCount(1)
    await expect(page.locator('.error-banner')).toHaveCount(0)
    await page.screenshot({ path: `../.runtime/browser-${route.replaceAll('/','') || 'dashboard'}.png`, fullPage: true })
  })
}

test('all nine navigation links and responsive navigation', async ({ page }) => {
  await page.goto('/')
  for (const [route] of routes) {
    await page.locator(`nav a[href="${route}"]`).click()
    await expect(page).toHaveURL(new RegExp(`${route === '/' ? '/$' : route.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+'$'}`))
    await expect(page.locator('h1')).toBeVisible()
  }
  await page.setViewportSize({ width: 390, height: 844 })
  await page.getByRole('button', { name: 'Open navigation' }).click()
  await page.locator('nav a[href="/agents"]').click()
  await expect(page.locator('h1')).toHaveText('Agent Directory')
})

test('agent credential expansions expose real proof details', async ({ page }) => {
  await page.goto('/agents')
  await expect(page.locator('.agent-card')).toHaveCount(4)
  for (const card of await page.locator('.agent-card').all()) {
    const result = page.waitForResponse(response => response.url().includes('/credentials') && response.status() === 200)
    await card.getByRole('button').click()
    const body = await (await result).json()
    await expect(card.locator('.credential-row')).toHaveCount(body.credentials.length)
    await expect(card.locator('.skeleton')).toHaveCount(0)
    await expect(card.locator('.error-banner')).toHaveCount(0)
    await card.getByRole('button').click()
  }
})

test('audit original and tampered proof controls and drawer', async ({ page, context }) => {
  await page.goto('/blockchain-audit')
  await expect(page.locator('.audit-table tbody tr')).toHaveCount(1)
  await expect(page.locator('#audit-action-select option')).toHaveCount(6)
  await page.locator('#audit-action-select').selectOption({ index: 1 })
  await expect(page.locator('.audit-record-summary')).toContainText('VERIFIED')
  for (let index = 2; index <= 5; index++) {
    await page.locator('#audit-action-select').selectOption({ index })
    await expect(page.locator('.audit-record-summary')).toContainText('VERIFIED')
  }
  await page.getByRole('button', { name: 'Test tamper detection' }).click()
  await expect(page.locator('.audit-record-summary')).toContainText('TAMPERED')
  await page.getByRole('button', { name: 'Verify action', exact: true }).click()
  await expect(page.locator('.audit-record-summary')).toContainText('VERIFIED')
  await page.locator('.audit-table tbody tr').click()
  await expect(page.getByRole('heading', { name: 'Batch details' })).toBeVisible()
  for (const link of await page.locator('.audit-drawer a').all()) {
    await expect(link).toHaveAttribute('href', /^https:\/\/sepolia\.etherscan\.io\/(tx|block|address)\//)
  }
  await context.grantPermissions(['clipboard-read', 'clipboard-write'])
  for (const button of await page.locator('.audit-drawer .audit-copy-value button').all()) {
    const value = (await button.getAttribute('aria-label')).slice(5)
    await button.click()
    await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toBe(value)
  }
  await page.getByRole('button', { name: 'Close batch details' }).click()
  await page.getByRole('button', { name: 'Refresh', exact: true }).click()
  await expect(page.getByRole('button', { name: 'Refresh', exact: true })).toBeEnabled()
})

test('evaluation filters and architecture controls', async ({ page }) => {
  await page.goto('/evaluation')
  await expect(page.locator('.evaluation-table-wrap tbody tr')).toHaveCount(5)
  for (const [label, count] of [['ALLOW',1],['BLOCK',3],['REVIEW',1],['ALL',5]]) {
    await page.getByRole('button', { name: label, exact: true }).click()
    await expect(page.locator('.evaluation-table-wrap tbody tr')).toHaveCount(count)
  }
  await expect(page.locator('.evaluation-architecture__flow button')).toHaveCount(7)
  for (const button of await page.locator('.evaluation-architecture__flow button').all()) {
    await button.click()
    await expect(page.locator('.evaluation-architecture__detail strong')).toHaveText(await button.locator('strong').textContent())
  }
})

test('revocation queries active revoked and unknown agents', async ({ page }) => {
  await page.goto('/revocation')
  for (const [id,status] of [['Agent_C','REVOKED'],['Agent_B','ACTIVE'],['Unknown_Agent','AGENT_NOT_FOUND']]) {
    await page.getByRole('combobox', { name: 'Agent to verify' }).selectOption(id)
    await expect(page.getByRole('button', { name: 'Check chain status' })).toBeEnabled()
    await page.getByRole('button', { name: 'Check chain status' }).click()
    await expect(page.locator('section.revocation-result')).toContainText(status)
  }
})

test('trust graph controls node and edge details and historical trace', async ({ page }) => {
  await page.goto('/trust-graph')
  await expect(page.locator('.react-flow__node')).toHaveCount(5)
  await page.locator('.react-flow__controls-zoomin').click()
  await page.locator('.react-flow__controls-zoomout').click()
  await page.locator('.react-flow__controls-fitview').click()
  await page.locator('.react-flow__node').filter({ hasText: 'Agent_B' }).click()
  await expect(page.locator('.graph-drawer')).toContainText('Agent_B')
  await page.getByRole('button', { name: 'Close details' }).click()
  await page.locator('.trust-edge__label').first().click()
  await expect(page.locator('.graph-drawer')).toContainText('PROOF VERIFIED')
  await page.getByRole('button', { name: 'Close details' }).click()
  await page.getByRole('button', { name: 'Run blockchain trace' }).click()
  await expect(page.locator('.trace-result')).toBeVisible()
  await page.getByRole('button', { name: 'Trace Agent_C post-revocation action' }).click()
  await expect(page.locator('.trace-result')).toContainText('AUTHORITY_REVOKED_AT_TIME_OF_ACTION')
})

test('threat modal buttons and all five governance scenarios', async ({ page }) => {
  await page.goto('/threat-lab')
  for (const card of await page.locator('.threat-card').all()) {
    await card.click(); await expect(page.getByRole('dialog')).toBeVisible()
    await page.getByRole('button', { name: 'Cancel', exact: true }).click()
    await card.click(); await page.getByRole('button', { name: 'Close', exact: true }).click()
  }
  await page.locator('.threat-card').first().click()
  await page.getByRole('button', { name: 'Open live pipeline' }).click()
  await expect(page).toHaveURL(/governance\?scenario=/)
  const buttons = page.locator('.governance-toolbar__scenarios button')
  const decisions = []
  page.on('websocket', socket => socket.on('framereceived', frame => {
    const event = JSON.parse(String(frame.payload))
    if (event.event === 'VERDICT_COMPLETE') decisions.push(event.decision)
  }))
  for (const [index,decision] of [[0,'ALLOW'],[1,'BLOCK'],[2,'BLOCK'],[3,'BLOCK'],[4,'REVIEW']]) {
    const before = decisions.length
    await buttons.nth(index).click()
    await expect.poll(() => decisions.length).toBeGreaterThan(before)
    expect(decisions.at(-1)).toBe(decision)
    await expect(page.locator('.verdict-visual')).toContainText(decision)
  }
})

test('complete automatic demo returns all five authenticated saved decisions', async ({ page }) => {
  const decisions = []
  page.on('websocket', socket => socket.on('framereceived', frame => {
    const event = JSON.parse(String(frame.payload))
    if (event.event === 'VERDICT_COMPLETE') decisions.push(event.decision)
  }))
  await page.goto('/governance?auto=1')
  await expect.poll(() => decisions.length, { timeout: 280000 }).toBe(5)
  expect(decisions).toEqual(['ALLOW','BLOCK','BLOCK','REVIEW','BLOCK'])
  await expect(page.locator('.verdict-visual')).toContainText('BLOCK')
  await expect(page.getByRole('button', { name: 'Pause', exact: true })).toHaveCount(0)
})

test('auto demo pause resume next restart and presentation navigation', async ({ page }) => {
  await page.goto('/governance')
  await page.getByRole('button', { name: 'Auto demo', exact: true }).click()
  await page.getByRole('button', { name: 'Pause', exact: true }).click()
  await page.getByRole('button', { name: 'Resume', exact: true }).click()
  await page.getByRole('button', { name: 'Next', exact: true }).click()
  await page.getByRole('button', { name: 'Restart', exact: true }).click()
  await page.getByRole('button', { name: 'Presentation Mode' }).click()
  await expect(page.locator('.presentation-bar')).toBeVisible()
  await page.locator('.presentation-bar').getByRole('button', { name: 'Next', exact: true }).click()
  await page.locator('.presentation-bar').getByRole('button', { name: 'Back', exact: true }).click()
  // The progress controls are intentionally hidden at the 1440px tablet
  // breakpoint; visible Back/Next controls cover navigation at this viewport.
  await expect(page.locator('.presentation-bar__progress')).toBeHidden()
  await page.getByRole('button', { name: 'Exit presentation mode', exact: true }).click()
})

test('loading shows unknown metadata without false local or offline labels', async ({ page }) => {
  let release
  const gate = new Promise(resolve => { release = resolve })
  await page.route('**/api/**', async route => { await gate; await route.continue() })
  await page.goto('/blockchain-audit')
  await expect(page.locator('.audit-network')).toContainText('CHECKING NETWORK')
  await expect(page.locator('.audit-network')).not.toContainText('Hardhat')
  await expect(page.locator('.audit-network')).not.toContainText('OFFLINE')
  await expect(page.locator('.network-card')).not.toContainText('Blockchain offline')
  release()
  await expect(page.locator('.audit-network')).toContainText('Ethereum Sepolia')
})

test('failure state is visible and retry recovers', async ({ page }) => {
  await page.route('**/api/**', route => route.abort('connectionrefused'))
  await page.goto('/blockchain-audit')
  await expect(page.locator('.audit-error')).toBeVisible()
  await expect(page.locator('.audit-network')).toContainText('NETWORK UNAVAILABLE')
  await expect(page.locator('.audit-network')).not.toContainText('Hardhat')
  await page.unroute('**/api/**')
  await page.locator('.audit-error').getByRole('button', { name: 'Retry' }).click()
  await page.locator('.system-alert').getByRole('button', { name: 'Retry' }).click()
  await expect(page.locator('.audit-network')).toContainText('RPC CONNECTED')
  await expect(page.locator('.topbar')).toContainText('System Online')
})

test('credential failure recovers when proof details are reopened', async ({ page }, info) => {
  info.expectedApiFailures = ['/api/agents/Agent_A/credentials']
  await page.route('**/api/agents/Agent_A/credentials', route => route.fulfill({status:503,contentType:'application/json',body:'{"detail":{"code":"EVIDENCE_UNAVAILABLE"}}'}))
  await page.goto('/agents')
  const card = page.locator('.agent-card').filter({has:page.getByRole('heading',{name:'Agent_A',exact:true})})
  await card.getByRole('button').click()
  await expect(card.locator('.error-banner')).toContainText('EVIDENCE_UNAVAILABLE')
  await card.getByRole('button').click()
  await page.unroute('**/api/agents/Agent_A/credentials')
  await card.getByRole('button').click()
  await expect(card.locator('.credential-row')).toHaveCount(1)
  await expect(card.locator('.error-banner')).toHaveCount(0)
})

test('graph drawer failure displays unavailable evidence without runtime errors', async ({ page }, info) => {
  info.expectedApiFailures = ['/api/agents/Agent_A/credentials']
  await page.route('**/api/agents/Agent_A/credentials', route => route.fulfill({status:503,contentType:'application/json',body:'{"detail":{"code":"EVIDENCE_UNAVAILABLE"}}'}))
  await page.goto('/trust-graph')
  await expect(page.locator('.react-flow__node')).toHaveCount(5)
  await page.locator('.react-flow__node').filter({hasText:'Agent_A'}).click()
  await expect(page.locator('.graph-drawer')).toContainText('Credential evidence unavailable')
  await expect(page.locator('.graph-drawer')).toContainText('UNAVAILABLE')
})

for (const malformed of [false,true]) {
  test(`WebSocket failure ${malformed ? 'malformed message' : 'early close'} exits processing`, async ({ page }) => {
    await page.routeWebSocket('**/ws/governance', socket => socket.onMessage(() => {
      if (malformed) socket.send('not-json')
      else socket.close({code:1011,reason:'Synthetic local failure'})
    }))
    await page.goto('/governance')
    await page.locator('.governance-toolbar__scenarios button').first().click()
    await expect(page.locator('.error-banner')).toContainText(malformed ? 'Invalid governance response' : 'closed before the verdict')
    await expect(page.locator('.verdict-visual')).toHaveCount(0)
  })
}


test('clipboard failure provides the full public value without false success', async ({ page }) => {
  await page.addInitScript(() => Object.defineProperty(navigator, 'clipboard', { value: { writeText: async () => { throw new Error('synthetic clipboard denial') } } }))
  await page.goto('/blockchain-audit')
  const copy = page.locator('.audit-network').getByRole('button', { name: /^Copy / }).first()
  const publicValue = (await copy.getAttribute('aria-label')).slice(5)
  await copy.click()
  await expect(page.getByRole('status').filter({ hasText: 'Clipboard unavailable' })).toContainText(publicValue)
  await expect(copy).not.toHaveAttribute('title', 'Copied')
})

test('paused replay reports PAUSED and never a premature complete state', async ({ page }) => {
  await page.goto('/governance')
  await page.getByRole('button', { name: 'Auto demo', exact: true }).click()
  await page.getByRole('button', { name: 'Pause', exact: true }).click()
  await expect(page.locator('.page-heading')).toContainText('PAUSED')
  await expect(page.locator('.page-heading')).not.toContainText('PIPELINE COMPLETE')
  await page.getByRole('button', { name: 'Resume', exact: true }).click()
  await expect(page.getByRole('button', { name: 'Pause', exact: true })).toBeVisible()
})

test('profile evidence does not hardcode a Sepolia provenance label', async ({ page }) => {
  await page.goto('/evaluation')
  await expect(page.getByText('Saved decisions for the selected network.', { exact: false })).toBeVisible()
  await expect(page.getByText('Saved Sepolia decisions.', { exact: false })).toHaveCount(0)
})


test('all graph proof labels select their own evidence at laptop size', async ({ page }) => {
  await page.setViewportSize({width:1366,height:768})
  const graphResponse = page.waitForResponse(response => response.url().includes('/api/delegation-graph') && response.status() === 200)
  await page.goto('/trust-graph')
  const evidence = await (await graphResponse).json()
  expect(evidence.edges.length).toBeGreaterThan(0)
  await expect(page.locator('.trust-edge__label')).toHaveCount(evidence.edges.length)
  for (let index=0;index<evidence.edges.length;index++) {
    const label=page.locator('.trust-edge__label').nth(index)
    const permission=await label.locator('span').textContent()
    await label.click()
    await expect(page.locator('.graph-drawer h3')).toHaveText(permission)
    await expect(page.locator('.graph-drawer')).toContainText('PROOF VERIFIED')
    await page.getByRole('button',{name:'Close details',exact:true}).click()
  }
})


test('signed action input rejects malformed JSON and unsigned requests clearly', async ({ page }) => {
  await page.goto('/governance')
  await page.getByText('Evaluate a signed action',{exact:true}).click()
  await page.getByRole('textbox',{name:'Action JSON',exact:true}).fill('{broken')
  await page.getByRole('textbox',{name:'Signed authentication JSON',exact:true}).fill('{}')
  await page.getByRole('button',{name:'Evaluate signed action',exact:true}).click()
  await expect(page.getByRole('alert')).toContainText('valid action JSON')
  await page.getByRole('textbox',{name:'Action JSON',exact:true}).fill(JSON.stringify({actor:'Agent_B',action:'USE_PERMISSION',permission:'CREATE_ORDER',timestamp:new Date().toISOString()}))
  await page.getByRole('button',{name:'Evaluate signed action',exact:true}).click()
  await expect(page.locator('.error-banner')).toContainText('INVALID_AUTHENTICATION')
  await expect(page.getByRole('textbox',{name:'Signed authentication JSON',exact:true})).toHaveValue('')
  await expect(page.locator('.verdict-visual')).toHaveCount(0)
})


test('unknown route shows a useful page and returns to the dashboard', async ({ page }) => {
  await page.goto('/qa-route-does-not-exist')
  await expect(page.getByRole('heading',{name:'Page not found',exact:true})).toBeVisible()
  await page.getByRole('link',{name:'Return to dashboard',exact:true}).click()
  await expect(page).toHaveURL(/\/$/)
  await expect(page.locator('.dashboard-agent:not(.skeleton)')).toHaveCount(4)
})
