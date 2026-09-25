/**
 * "Currently silent devices" section on the Alerts page, tested against a
 * real backend+frontend+Postgres. Needs at least one existing
 * device_silence_state row to meaningfully verify rendering (written by
 * ml/detect_silent_devices.py in production; inserted directly for this
 * test).
 *
 * Usage: node e2e/test_device_silence.mjs (needs backend+frontend running
 * and an admin/analyst account, same as smoke.mjs).
 */
import { chromium } from 'playwright'

const base = process.env.BASE_URL ?? 'http://127.0.0.1:5173'
const username = process.env.ADMIN_USERNAME ?? 'admin'
const password = process.env.ADMIN_PASSWORD

if (!password) {
  console.error('Set ADMIN_PASSWORD to an existing admin/analyst account\'s password before running this script.')
  process.exit(1)
}

const browser = await chromium.launch()
const page = await browser.newPage()

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

await page.goto(base + '/alerts')
await page.waitForSelector('h3:has-text("Currently silent devices")')
console.log('Silent-devices section found')

await page.waitForTimeout(500)
const rows = await page.$$eval(
  'h3:has-text("Currently silent devices") + p + table tbody tr',
  (trs) => trs.map((tr) => tr.innerText),
)
console.log('Rows found:', rows.length)
rows.forEach((r) => console.log('  ', r.replace(/\n/g, ' | ')))

await page.screenshot({ path: '/tmp/device_silence_screenshot.png', fullPage: true })
console.log('Screenshot saved to /tmp/device_silence_screenshot.png')

if (failedResponses.length) {
  console.error('Unexpected failed responses:', failedResponses)
  process.exitCode = 1
} else {
  console.log('No unexpected API failures')
}

await browser.close()
