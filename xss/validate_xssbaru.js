const { chromium } = require('playwright');

(async () => {
  const url = process.argv[2];
  if (!url) {
    console.error("❌ URL tidak diberikan.");
    process.exit(1);
  }

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();

  let triggered = false;

  page.on('dialog', async dialog => {
    triggered = true;
    console.log(`[✓] Alert triggered: "${dialog.message()}"`);
    await dialog.dismiss();
  });

  try {
    await page.goto(url, { waitUntil: 'load', timeout: 10000 });
    await page.waitForTimeout(5000);
  } catch (e) {
    console.error(`[x] Gagal membuka URL: ${url}`);
  }

  await browser.close();
  if (!triggered) {
    console.log(`[x] Tidak ada alert untuk: ${url}`);
    process.exit(2);
  }
})();
