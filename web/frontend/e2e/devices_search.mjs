/**
 * Devices page search/filter form (hostname, IP, vendor, start/end), tested
 * against a real browser with /api/devices mocked via Playwright's route
 * interception -- same rationale as devices_pagination.mjs: verifying the
 * exact query params a filter sends needs a deterministic mock, not a real
 * ClickHouse instance.
 *
 * Usage: node e2e/devices_search.mjs (needs backend+frontend running and an
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

const requests = []
await page.route('**/api/devices?*', async (route) => {
  const url = new URL(route.request().url())
  const params = Object.fromEntries(url.searchParams.entries())
  requests.push(params)
  await route.fulfill({
    contentType: 'application/json',
    body: JSON.stringify({ items: [], limit: Number(params.limit), offset: Number(params.offset), has_more: false }),
  })
})
await page.route('**/api/devices/resolution-summary', async (route) => {
  await route.fulfill({ contentType: 'application/json', body: JSON.stringify([]) })
})

console.log('1. Login')
await page.goto(base + '/login')
await page.fill('input[required]', username)
await page.fill('input[type=password]', password)
await page.click('button[type=submit]')
await page.waitForURL(base + '/')
await page.waitForSelector('table.data-table')

console.log('2. Initial request has no hostname/ip/vendor/start/end params')
let req = requests[requests.length - 1]
console.log('   ', req)
if (req.hostname || req.ip || req.vendor || req.start || req.end) {
  throw new Error('Unexpected filter params on initial load')
}

console.log('3. Fill hostname + ip + vendor, click Search -> filters sent, offset reset to 0')
await page.fill('input[type=text] >> nth=0', 'router')
await page.fill('input[type=text] >> nth=1', '10.0.0')
await page.fill('input[type=text] >> nth=2', 'cisco')
await page.click('button:has-text("Search")')
await page.waitForTimeout(300)
req = requests[requests.length - 1]
console.log('   ', req)
if (req.hostname !== 'router' || req.ip !== '10.0.0' || req.vendor !== 'cisco') {
  throw new Error('Filters not sent correctly')
}
if (req.offset !== '0') throw new Error('Search did not reset offset to 0')

console.log('4. Click Clear -> filters removed, another request fires')
const callsBefore = requests.length
await page.click('button:has-text("Clear")')
await page.waitForTimeout(300)
if (requests.length <= callsBefore) throw new Error('Clear did not trigger a reload')
req = requests[requests.length - 1]
console.log('   ', req)
if (req.hostname || req.ip || req.vendor) throw new Error('Clear did not remove filters')

console.log('\nALL DEVICE SEARCH FILTER CHECKS PASSED')
await browser.close()
