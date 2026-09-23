/**
 * Log Search page-size selector and CSV/XML export, tested against a real
 * browser with /api/logs/search and /api/logs/export mocked via
 * Playwright's route interception -- same rationale as the devices_*
 * tests: exercising specific page sizes and download behavior needs a
 * deterministic mock, not a real ClickHouse instance.
 *
 * Usage: node e2e/logs_export.mjs (needs backend+frontend running and an
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

const searchRequests = []
const exportRequests = []

const SAMPLE_ITEM = {
  event_time: '2026-09-23T04:30:30Z',
  source_ip: '172.22.14.247',
  hostname: 'ACSSERVER',
  vendor: 'cisco',
  severity: 'notice',
  program: 'async,ppp,info',
  pid: null,
  message: 'ppp-out1: waiting for packets...',
  predicted_category: 'UNKNOWN',
  predicted_confidence: 0,
  is_anomaly: false,
  anomaly_reasons: [],
  resolution_method: 'syslog_reported',
}

await page.route('**/api/logs/search?*', async (route) => {
  const url = new URL(route.request().url())
  const params = Object.fromEntries(url.searchParams.entries())
  searchRequests.push(params)
  const limit = Number(params.limit || 100)
  const items = Array.from({ length: Math.min(limit, 30) }, (_, i) => ({ ...SAMPLE_ITEM, message: `msg ${i}` }))
  await route.fulfill({
    contentType: 'application/json',
    body: JSON.stringify({ items, limit, offset: Number(params.offset || 0), has_more: limit < 30 }),
  })
})

await page.route('**/api/logs/export?*', async (route) => {
  const url = new URL(route.request().url())
  const params = Object.fromEntries(url.searchParams.entries())
  exportRequests.push(params)
  const format = params.format
  const body = format === 'xml' ? '<?xml version="1.0"?><logs><log/></logs>' : 'event_time,source_ip\nfoo,bar\n'
  await route.fulfill({
    status: 200,
    contentType: format === 'xml' ? 'application/xml' : 'text/csv',
    headers: { 'content-disposition': `attachment; filename="logs_export.${format}"` },
    body,
  })
})

console.log('1. Login')
await page.goto(base + '/login')
await page.fill('input[required]', username)
await page.fill('input[type=password]', password)
await page.click('button[type=submit]')
await page.waitForURL(base + '/')
await page.goto(base + '/logs')
await page.waitForSelector('table.data-table')

console.log('2. Default page size 50 -> first request has limit=50')
let req = searchRequests[searchRequests.length - 1]
console.log('   ', req)
if (req.limit !== '50') throw new Error('Unexpected default page size')

console.log('3. Change page size to 10 -> resets offset, requests limit=10')
await page.selectOption('label:has-text("Per page") select', '10')
await page.waitForTimeout(300)
req = searchRequests[searchRequests.length - 1]
console.log('   ', req)
if (req.limit !== '10' || req.offset !== '0') throw new Error('Page size change did not work correctly')
let rows = await page.locator('tbody tr').count()
if (rows !== 10) throw new Error(`Expected 10 rows, got ${rows}`)

console.log('4. Click Next -> offset becomes 10 with the new page size')
await page.click('button:has-text("Next")')
await page.waitForTimeout(300)
req = searchRequests[searchRequests.length - 1]
console.log('   ', req)
if (req.offset !== '10' || req.limit !== '10') throw new Error('Next did not use pageSize correctly')

console.log('5. Export CSV -> triggers a download with format=csv')
const [download1] = await Promise.all([
  page.waitForEvent('download'),
  page.click('button:has-text("Export CSV")'),
])
console.log('   suggested filename:', download1.suggestedFilename())
if (download1.suggestedFilename() !== 'logs_export.csv') throw new Error('Unexpected CSV filename')
let exportReq = exportRequests[exportRequests.length - 1]
if (exportReq.format !== 'csv') throw new Error('Export format param not sent correctly')

console.log('6. Export XML -> triggers a download with format=xml')
const [download2] = await Promise.all([
  page.waitForEvent('download'),
  page.click('button:has-text("Export XML")'),
])
console.log('   suggested filename:', download2.suggestedFilename())
if (download2.suggestedFilename() !== 'logs_export.xml') throw new Error('Unexpected XML filename')
exportReq = exportRequests[exportRequests.length - 1]
if (exportReq.format !== 'xml') throw new Error('Export format param not sent correctly')

console.log('7. Export respects applied filters (fill hostname, search, then export)')
const hostnameInputs = await page.locator('input[type=text]').all()
await hostnameInputs[1].fill('ACSSERVER')
await page.click('button:has-text("Search")')
await page.waitForTimeout(300)
await Promise.all([page.waitForEvent('download'), page.click('button:has-text("Export CSV")')])
exportReq = exportRequests[exportRequests.length - 1]
console.log('   export request params after filtering:', exportReq)
if (exportReq.hostname !== 'ACSSERVER') throw new Error('Export did not carry the applied hostname filter')

console.log('\nALL LOG SEARCH PAGE-SIZE + EXPORT CHECKS PASSED')
await browser.close()
