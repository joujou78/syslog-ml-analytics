/**
 * Devices page pagination + auto-refresh, tested against a real browser
 * with /api/devices and /api/devices/resolution-summary mocked via
 * Playwright's route interception -- unlike smoke.mjs, this doesn't run
 * against a real backend, since exercising specific page counts/offsets
 * needs a deterministic dataset that no live ClickHouse instance can
 * promise (and none is available in this sandbox anyway). Uses
 * Playwright's clock API to fast-forward past the 30s auto-refresh
 * interval without an actual 30-second wait.
 *
 * Usage: node e2e/devices_pagination.mjs (needs backend+frontend running
 * and an admin account, same as smoke.mjs -- see its header for how to
 * start both).
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

// Track every /api/devices request Playwright intercepts, and serve a
// deterministic fake dataset so this test doesn't depend on real ClickHouse.
const requests = []
function makeItems(offset, limit, total) {
  const items = []
  for (let i = offset; i < Math.min(offset + limit, total); i++) {
    items.push({
      ip: `10.0.0.${i}`,
      hostname: `host-${i}`,
      vendor: 'unknown',
      vendor_source: 'unknown',
      model: '',
      resolution_method: 'unresolved',
      first_seen_in_window: new Date().toISOString(),
      last_seen: new Date().toISOString(),
      event_count: i,
    })
  }
  return items
}

const TOTAL_DEVICES = 30
let callCount = 0

await page.route('**/api/devices?*', async (route) => {
  const url = new URL(route.request().url())
  const limit = Number(url.searchParams.get('limit'))
  const offset = Number(url.searchParams.get('offset'))
  requests.push({ limit, offset })
  callCount++
  const items = makeItems(offset, limit, TOTAL_DEVICES)
  await route.fulfill({
    contentType: 'application/json',
    body: JSON.stringify({ items, limit, offset, has_more: offset + limit < TOTAL_DEVICES }),
  })
})

await page.route('**/api/devices/resolution-summary', async (route) => {
  await route.fulfill({
    contentType: 'application/json',
    body: JSON.stringify([{ resolution_method: 'unresolved', device_count: TOTAL_DEVICES }]),
  })
})

await page.clock.install()

console.log('1. Login')
await page.goto(base + '/login')
await page.fill('input[required]', username)
await page.fill('input[type=password]', password)
await page.click('button[type=submit]')
await page.waitForURL(base + '/')
await page.waitForSelector('table.data-table')

console.log('2. Default page size should be 25 -> first request has limit=25, offset=0')
let firstReq = requests[requests.length - 1]
console.log('   request:', firstReq)
if (firstReq.limit !== 25 || firstReq.offset !== 0) throw new Error('Unexpected initial request')
let rows = await page.locator('tbody tr').count()
console.log('   rows rendered:', rows)
if (rows !== 25) throw new Error(`Expected 25 rows, got ${rows}`)

console.log('3. Click Next -> should request offset=25')
await page.click('button:has-text("Next")')
await page.waitForTimeout(300)
let lastReq = requests[requests.length - 1]
console.log('   request:', lastReq)
if (lastReq.offset !== 25) throw new Error('Next did not advance offset correctly')
rows = await page.locator('tbody tr').count()
console.log('   rows rendered on page 2:', rows)
if (rows !== 5) throw new Error(`Expected 5 rows on last page (30 total, 25+5), got ${rows}`)

console.log('4. Next button should now be disabled (no more pages)')
const nextDisabled = await page.locator('button:has-text("Next")').isDisabled()
console.log('   Next disabled:', nextDisabled)
if (!nextDisabled) throw new Error('Next should be disabled on the last page')

console.log('5. Click Previous -> back to offset=0')
await page.click('button:has-text("Previous")')
await page.waitForTimeout(300)
lastReq = requests[requests.length - 1]
if (lastReq.offset !== 0) throw new Error('Previous did not return to offset 0')
console.log('   OK, back at offset 0')

console.log('6. Change page size to 10 -> should reset offset to 0 and request limit=10')
await page.selectOption('select', '10')
await page.waitForTimeout(300)
lastReq = requests[requests.length - 1]
console.log('   request:', lastReq)
if (lastReq.limit !== 10 || lastReq.offset !== 0) throw new Error('Page size change did not reset correctly')
rows = await page.locator('tbody tr').count()
if (rows !== 10) throw new Error(`Expected 10 rows, got ${rows}`)

console.log('7. Auto-refresh: fast-forward virtual clock 30s, expect another /api/devices call at the SAME offset/limit')
const callsBefore = callCount
await page.clock.fastForward('00:31')
await page.waitForTimeout(300)
const callsAfter = callCount
console.log('   calls before:', callsBefore, 'after fast-forward:', callsAfter)
if (callsAfter <= callsBefore) throw new Error('Auto-refresh did not fire a new request')
const refreshReq = requests[requests.length - 1]
if (refreshReq.limit !== 10 || refreshReq.offset !== 0) throw new Error('Auto-refresh changed pagination unexpectedly')
console.log('   OK, auto-refresh fired without disturbing pageSize/offset')

console.log('\nALL DEVICE PAGINATION/AUTO-REFRESH CHECKS PASSED')
await browser.close()
