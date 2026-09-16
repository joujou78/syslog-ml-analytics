/**
 * Browser smoke test against a running instance of the app (backend +
 * frontend dev server, or a built+served frontend). Not a substitute for
 * proper test coverage -- it's a fast sanity check that the core auth/RBAC/
 * persistence flows actually work end to end in a real browser, since
 * type-checking and unit tests don't catch wiring mistakes between them.
 *
 * Requires an existing admin account (see scripts/create_admin.py in
 * web/backend) and assumes ClickHouse may NOT be running -- it tolerates
 * (but reports) 500s from the ClickHouse-backed /devices endpoints.
 *
 * Usage:
 *   BASE_URL=http://127.0.0.1:5173 ADMIN_USERNAME=admin ADMIN_PASSWORD=... \
 *     node e2e/smoke.mjs
 */
import { chromium } from 'playwright'

const base = process.env.BASE_URL ?? 'http://127.0.0.1:5173'
const username = process.env.ADMIN_USERNAME ?? 'admin'
const password = process.env.ADMIN_PASSWORD
const testIp = `10.254.254.${Math.floor(Math.random() * 254) + 1}`

if (!password) {
  console.error('Set ADMIN_PASSWORD to an existing admin account\'s password before running this script.')
  process.exit(1)
}

const browser = await chromium.launch()
const page = await browser.newPage()

// Track failed HTTP responses by URL so expected failures (the deliberate
// wrong-password 401, and /devices 500s when ClickHouse isn't running)
// can be told apart from genuine regressions.
const failedResponses = []
page.on('pageerror', (e) => failedResponses.push({ url: '(uncaught exception)', detail: String(e) }))
page.on('response', (response) => {
  if (response.status() >= 400) {
    failedResponses.push({ url: response.url(), status: response.status() })
  }
})

const isExpectedFailure = (f) =>
  f.url.includes('/api/devices') || (f.url.includes('/api/auth/login') && f.status === 401)

console.log('1. Load app while logged out -> should redirect to /login')
await page.goto(base + '/')
await page.waitForURL('**/login')
console.log('   OK, at', page.url())

console.log('2. Wrong password -> should show error, stay on /login')
await page.fill('input[required]', username)
await page.fill('input[type=password]', 'definitely-wrong-password')
await page.click('button[type=submit]')
await page.waitForSelector('.form-error')
console.log('   OK, error shown:', await page.textContent('.form-error'))

console.log('3. Correct login -> should land on Devices page')
await page.fill('input[type=password]', password)
await page.click('button[type=submit]')
await page.waitForURL(base + '/')
await page.waitForSelector('h2')
console.log('   OK, heading:', await page.textContent('h2'))

console.log('4. Nav shows admin-only "SNMP Credentials" link for admin user')
const navText = await page.textContent('.app-nav')
if (!navText.includes('SNMP Credentials')) throw new Error('Credentials nav link missing for admin')
console.log('   OK')

console.log('5. Navigate to Credentials page and add a credential')
await page.click('text=SNMP Credentials')
await page.waitForURL('**/credentials')
await page.fill('input[placeholder*="10.10.1.5"]', testIp)
await page.fill('input[type=password]', 'e2e-test-community')
await page.click('button:has-text("Add credential")')
await page.waitForSelector(`td.mono:has-text("${testIp}")`)
console.log('   OK, credential row appeared for', testIp)

console.log('6. Reload page, credential should persist (from backend, not local state)')
await page.reload()
await page.waitForSelector(`td.mono:has-text("${testIp}")`)
console.log('   OK, persisted after reload')

console.log('7. Clean up: delete the test credential')
page.once('dialog', (d) => d.accept())
const row = page.locator('tr', { has: page.locator(`td.mono:has-text("${testIp}")`) })
await row.locator('button:has-text("Delete")').click()
await page.waitForSelector(`td.mono:has-text("${testIp}")`, { state: 'detached' })
console.log('   OK, cleaned up')

console.log('8. Log out -> back to /login, and protected route redirects again')
await page.click('text=Log out')
await page.waitForURL('**/login')
await page.goto(base + '/credentials')
await page.waitForURL('**/login')
console.log('   OK')

const unexpected = failedResponses.filter((f) => !isExpectedFailure(f))
const expected = failedResponses.filter(isExpectedFailure)
await browser.close()

if (unexpected.length) {
  console.log('\nUnexpected failed requests/exceptions:')
  for (const f of unexpected) console.log(' -', f.status ?? '', f.url, f.detail ?? '')
  process.exit(1)
}

console.log('\nALL SMOKE CHECKS PASSED')
if (expected.length) {
  console.log(`(${expected.length} expected failure(s) observed: the deliberate wrong-password 401, and /devices errors if ClickHouse isn't running)`)
}
