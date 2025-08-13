import { chromium } from 'playwright';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const axe = require('axe-core');

/**
 * Crawl a website and run axe-core accessibility scanning on each page
 * @param {string} startUrl - The URL to start scanning from
 * @param {object} opts - Options like maxPages
 * @returns {object} Scan results with violations and compliance score
 */
export async function crawlAndScan(startUrl, opts = {}) {
  const maxPages = Math.min(Math.max(opts.maxPages ?? 50, 1), 200); // Limit to 200 pages max
  const origin = new URL(startUrl).origin;

  console.log(`Starting scan of ${startUrl} (max ${maxPages} pages)`);

  const browser = await chromium.launch({ 
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox'] // Railway compatibility
  });
  
  const context = await browser.newContext({
    userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
  });
  
  const page = await context.newPage();

  const queue = new Set([startUrl]);
  const seen = new Set();
  const results = [];

  try {
    while (queue.size && results.length < maxPages) {
      const current = queue.values().next().value;
      queue.delete(current);
      
      if (seen.has(current)) continue;
      seen.add(current);

      console.log(`Scanning page ${results.length + 1}/${maxPages}: ${current}`);

      try {
        await page.goto(current, { 
          waitUntil: 'domcontentloaded', 
          timeout: 30000 
        });

        // Wait a bit for dynamic content to load
        await page.waitForTimeout(1000);

        // Inject axe-core with CSP-safe method
        await page.addScriptTag({ content: axe.source });

        // Run axe-core accessibility scan
        const runResult = await page.evaluate(async () => {
          const res = await window.axe.run(document, {
            runOnly: {
              type: 'tag',
              values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22a', 'wcag22aa']
            },
            resultTypes: ['violations']
          });
          return res;
        });

        const violations = runResult?.violations ?? [];
        results.push({
          url: current,
          violations,
          scannedAt: new Date().toISOString()
        });

        // Find same-origin links to crawl next
        const links = await page.$$eval('a[href]', (anchors) =>
          Array.from(anchors)
            .map((a) => a.getAttribute('href'))
            .filter(Boolean)
        );

        for (const href of links) {
          try {
            const target = new URL(href, current);
            if (target.origin === origin && 
                !target.hash && 
                !seen.has(target.href) &&
                !target.pathname.match(/\.(pdf|jpg|jpeg|png|gif|zip|doc|docx)$/i)) {
              queue.add(target.href);
            }
          } catch (e) {
            // Invalid URL, skip
          }
        }
      } catch (err) {
        console.error(`Error scanning ${current}:`, err.message);
        results.push({
          url: current,
          error: String(err),
          violations: []
        });
      }
    }
  } finally {
    await browser.close();
  }

  // Calculate summary statistics
  let totalViolations = 0;
  const byImpact = { critical: 0, serious: 0, moderate: 0, minor: 0 };
  
  for (const result of results) {
    for (const violation of result.violations ?? []) {
      const nodeCount = violation.nodes?.length || 1;
      totalViolations += nodeCount;
      
      if (violation.impact && byImpact[violation.impact] !== undefined) {
        byImpact[violation.impact] += nodeCount;
      }
    }
  }

  const totalPages = results.length;
  
  // Calculate compliance score (0-100, higher is better)
  const violationDensity = totalViolations / Math.max(totalPages, 1);
  const complianceScore = Math.max(0, Math.min(100, 100 - Math.round(violationDensity * 2)));

  console.log(`Scan complete: ${totalPages} pages, ${totalViolations} violations, ${complianceScore}% compliance`);

  return {
    startUrl,
    scannedAt: new Date().toISOString(),
    totalPages,
    totalViolations,
    byImpact,
    complianceScore,
    pages: results
  };
}
