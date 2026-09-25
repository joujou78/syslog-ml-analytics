/**
 * Audit Log page, tested against a real backend+frontend+Postgres -- needs
 * at least one existing audit_log row to meaningfully verify rendering and
 * the action filter (any admin action -- creating an alert rule, an SNMP
 * credential, etc. -- writes one; see the individual _log_audit call sites
 * across web/backend/app/services/*.py).
 *
 * Usage: node e2e/test_audit_log.mjs (needs backend+frontend running and an
 * admin account, same as smoke.mjs -- see its header for how to start both).
 */
import { chromium } from 'playwright'

const base = process.env.BASE_URL ?? 'http://127.0.0.1:5173'
const username = process.env.ADMIN_USERNAME ?? 'admin'
const password = process.env.ADMIN_PASSWORD

if (!password) {
  console.error('Set ADMIN_PASSWORD to an existing admin account\'s password before running this script.')
  process.exit(1)
}

const browser = await chromium.launch()
const page = await browser.newPage()

// Login redirects to "/" (the Devices page) before this script navigates
// to /audit-log -- Devices' own API calls fire regardless and fail if
// ClickHouse isn't running, same expected/tolerated case smoke.mjs
// documents. Not this test's concern either way.
const failedResponses = []
page.on('pageerror', (e) => failedResponses.push(String(e)))
page.on('response', (r) => {
  if (r.status() >= 400 && r.url().includes('/api/') && !r.url().includes('/api/devices')) {
    failedResponses.push(`${r.status()} ${r.url()}`)
  }
})

await page.goto(base + '/login')
await page.fill('input[required]', username)
await page.fill('input[type=password]', password)
await page.click('button[type=submit]')
await page.waitForURL(base + '/')
console.log('Logged in OK')

const navText = await page.textContent('.app-nav')
if (!navText.includes('Audit Log')) throw new Error('Audit Log nav link missing for admin user')
console.log('Nav link present')

await page.click('text=Audit Log')
await page.waitForURL(base + '/audit-log')
await page.waitForSelector('h2:has-text("Audit Log")')
console.log('Landed on Audit Log page')

await page.waitForTimeout(500)
const rows = await page.$$eval('table.data-table tbody tr', (trs) => trs.map((tr) => tr.innerText))
console.log('Rows found:', rows.length)
rows.forEach((r) => console.log('  ', r.replace(/\n/g, ' | ')))

const options = await page.$$eval('select option', (opts) => opts.map((o) => o.textContent))
console.log('Action filter options:', options)

if (options.length > 1) {
  const targetAction = options[1]
  await page.selectOption('select', { label: targetAction })
  await page.waitForTimeout(500)
  const filteredRows = await page.$$eval('table.data-table tbody tr', (trs) => trs.map((tr) => tr.innerText))
  console.log(`After filtering by "${targetAction}":`, filteredRows.length, 'row(s)')
  const allMatch = filteredRows.every((r) => r.includes(targetAction))
  console.log('All filtered rows match the selected action:', allMatch)
}

await page.screenshot({ path: '/tmp/audit_log_screenshot.png', fullPage: true })
console.log('Screenshot saved to /tmp/audit_log_screenshot.png')

if (failedResponses.length) {
  console.error('Unexpected failed responses:', failedResponses)
  process.exitCode = 1
} else {
  console.log('No unexpected API failures')
}

await browser.close()
