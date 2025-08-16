import { chromium } from 'playwright';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const axe = require('axe-core');

/**
 * Enhanced accessibility scanner with improved accuracy and coverage
 * PRODUCTION VERSION - Optimized for SentryPrime backend deployment
 * 
 * Key improvements over original:
 * - Comprehensive axe-core rule coverage (80+ rules vs 20)
 * - Better dynamic content handling (4+ seconds vs 1 second)
 * - Enhanced page discovery with sitemap support
 * - Retry logic with exponential backoff
 * - Detailed logging and error handling
 * - Better violation counting and analysis
 */
export async function crawlAndScan(startUrl, opts = {}) {
  const maxPages = Math.min(Math.max(opts.maxPages ?? 50, 1), 200);
  const origin = new URL(startUrl).origin;

  console.log(`🔍 Starting enhanced accessibility scan of ${startUrl} (max ${maxPages} pages)`);

  const browser = await chromium.launch({ 
    headless: true,
    args: [
      '--no-sandbox', 
      '--disable-setuid-sandbox',
      '--disable-web-security',
      '--disable-features=VizDisplayCompositor',
      '--disable-dev-shm-usage', // Railway compatibility
      '--no-first-run',
      '--disable-gpu'
    ]
  });
  
  const context = await browser.newContext({
    userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    viewport: { width: 1280, height: 720 },
    ignoreHTTPSErrors: true
  });
  
  const page = await context.newPage();

  const queue = new Set([startUrl]);
  const seen = new Set();
  const results = [];
  const errors = [];

  try {
    // Discover additional pages via sitemap
    await discoverSitemapUrls(startUrl, queue, origin);
    
    while (queue.size && results.length < maxPages) {
      const current = queue.values().next().value;
      queue.delete(current);
      
      if (seen.has(current)) continue;
      seen.add(current);

      console.log(`📄 Scanning page ${results.length + 1}/${maxPages}: ${current}`);

      const pageResult = await scanPageWithRetry(page, current, 3);
      
      if (pageResult.success) {
        results.push(pageResult.data);
        
        // Discover more pages from current page
        const newLinks = await discoverPageLinks(page, current, origin);
        for (const link of newLinks) {
          if (!seen.has(link) && queue.size + results.length < maxPages) {
            queue.add(link);
          }
        }
      } else {
        errors.push({ url: current, error: pageResult.error });
        console.error(`❌ Failed to scan ${current}: ${pageResult.error}`);
      }
    }
  } finally {
    await browser.close();
  }

  // Analyze results with enhanced metrics
  const analysis = analyzeResults(results);
  
  console.log(`✅ Enhanced scan completed:`);
  console.log(`   📄 Pages scanned: ${analysis.totalPages}`);
  console.log(`   🚨 Total violations: ${analysis.totalViolations}`);
  console.log(`   📊 By impact: Critical(${analysis.byImpact.critical}) Serious(${analysis.byImpact.serious}) Moderate(${analysis.byImpact.moderate}) Minor(${analysis.byImpact.minor})`);
  console.log(`   📈 Compliance score: ${analysis.complianceScore}%`);
  console.log(`   ❌ Failed pages: ${errors.length}`);

  return {
    startUrl,
    scannedAt: new Date().toISOString(),
    totalPages: analysis.totalPages,
    totalViolations: analysis.totalViolations,
    byImpact: analysis.byImpact,
    complianceScore: analysis.complianceScore,
    pages: results,
    errors: errors.length > 0 ? errors : undefined,
    scannerVersion: 'enhanced-v2.0'
  };
}

/**
 * Scan a single page with comprehensive retry logic
 */
async function scanPageWithRetry(page, url, maxRetries = 3) {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      await page.goto(url, { 
        waitUntil: 'domcontentloaded', 
        timeout: 45000
      });

      // Enhanced dynamic content loading
      await page.waitForTimeout(2000);
      
      // Wait for common loading states
      try {
        await page.waitForFunction(() => {
          // Check for common loading indicators
          const loadingElements = document.querySelectorAll('[data-loading="true"], .loading, .spinner, [aria-busy="true"]');
          return loadingElements.length === 0;
        }, { timeout: 3000 });
      } catch (e) {
        // Continue if no loading indicators found
      }
      
      // Additional wait for JavaScript frameworks
      await page.waitForTimeout(2000);

      // Inject axe-core
      await page.addScriptTag({ content: axe.source });

      // Run comprehensive accessibility scan
      const runResult = await page.evaluate(async () => {
        try {
          // Use ALL available axe-core rules for maximum coverage
          const result = await window.axe.run(document, {
            runOnly: {
              type: 'rule',
              values: [
                // WCAG 2.0 Level A & AA
                'area-alt', 'aria-allowed-attr', 'aria-allowed-role', 'aria-command-name',
                'aria-hidden-body', 'aria-hidden-focus', 'aria-input-field-name', 'aria-meter-name',
                'aria-progressbar-name', 'aria-required-attr', 'aria-required-children',
                'aria-required-parent', 'aria-roles', 'aria-text', 'aria-toggle-field-name',
                'aria-tooltip-name', 'aria-treeitem-name', 'aria-valid-attr-value', 'aria-valid-attr',
                'audio-caption', 'blink', 'button-name', 'bypass', 'color-contrast',
                'color-contrast-enhanced', 'definition-list', 'dlitem', 'document-title',
                'duplicate-id', 'duplicate-id-active', 'duplicate-id-aria', 'empty-heading',
                'focus-order-semantics', 'form-field-multiple-labels', 'frame-title',
                'heading-order', 'hidden-content', 'html-has-lang', 'html-lang-valid',
                'identical-links-same-purpose', 'image-alt', 'image-redundant-alt',
                'input-button-name', 'input-image-alt', 'keyboard', 'label', 'label-content-name-mismatch',
                'label-title-only', 'landmark-banner-is-top-level', 'landmark-complementary-is-top-level',
                'landmark-contentinfo-is-top-level', 'landmark-main-is-top-level', 'landmark-no-duplicate-banner',
                'landmark-no-duplicate-contentinfo', 'landmark-no-duplicate-main', 'landmark-one-main',
                'landmark-unique', 'layout-table', 'link-in-text-block', 'link-name', 'list',
                'listitem', 'marquee', 'meta-refresh', 'meta-viewport', 'meta-viewport-large',
                'nested-interactive', 'no-autoplay-audio', 'object-alt', 'p-as-heading',
                'page-has-heading-one', 'presentation-role-conflict', 'region', 'role-img-alt',
                'scope-attr-valid', 'scrollable-region-focusable', 'server-side-image-map',
                'skip-link', 'svg-img-alt', 'table-caption', 'table-duplicate-name',
                'table-fake-caption', 'tabindex', 'td-has-header', 'td-headers-attr',
                'th-has-data-cells', 'valid-lang', 'video-caption',
                
                // WCAG 2.1 additions
                'autocomplete-valid', 'avoid-inline-spacing', 'css-orientation-lock',
                
                // WCAG 2.2 additions
                'target-size', 'focus-visible',
                
                // Additional important accessibility rules
                'accesskeys', 'aria-prohibited-attr'
              ]
            },
            resultTypes: ['violations', 'incomplete'],
            reporter: 'v2'
          });
          
          return result;
        } catch (axeError) {
          console.error('Axe-core comprehensive scan failed, falling back to basic scan:', axeError);
          // Fallback to basic WCAG scan
          return await window.axe.run(document, {
            runOnly: {
              type: 'tag',
              values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22a', 'wcag22aa']
            },
            resultTypes: ['violations']
          });
        }
      });

      const violations = runResult?.violations ?? [];
      const incomplete = runResult?.incomplete ?? [];
      
      // Enhanced violation logging
      const totalViolationInstances = violations.reduce((sum, v) => sum + (v.nodes?.length || 1), 0);
      if (totalViolationInstances > 0) {
        console.log(`   🚨 Found ${violations.length} violation types with ${totalViolationInstances} total instances`);
      }

      return {
        success: true,
        data: {
          url,
          violations,
          incomplete,
          scannedAt: new Date().toISOString()
        }
      };

    } catch (err) {
      console.error(`❌ Attempt ${attempt}/${maxRetries} failed for ${url}: ${err.message}`);
      
      if (attempt === maxRetries) {
        return {
          success: false,
          error: `Failed after ${maxRetries} attempts: ${err.message}`
        };
      }
      
      // Exponential backoff
      await new Promise(resolve => setTimeout(resolve, attempt * 2000));
    }
  }
}

/**
 * Discover URLs from sitemap.xml
 */
async function discoverSitemapUrls(startUrl, queue, origin) {
  try {
    const sitemapUrl = `${origin}/sitemap.xml`;
    console.log(`🗺️  Checking sitemap: ${sitemapUrl}`);
    
    const response = await fetch(sitemapUrl, { timeout: 10000 });
    if (response.ok) {
      const sitemapText = await response.text();
      const urlMatches = sitemapText.match(/<loc>(.*?)<\/loc>/g);
      
      if (urlMatches) {
        let addedCount = 0;
        for (const match of urlMatches.slice(0, 50)) { // Limit sitemap URLs
          const url = match.replace(/<\/?loc>/g, '');
          if (url.startsWith(origin) && 
              !url.match(/\.(pdf|jpg|jpeg|png|gif|zip|doc|docx|xml)$/i) &&
              !url.includes('/admin/') &&
              !url.includes('/wp-admin/')) {
            queue.add(url);
            addedCount++;
          }
        }
        console.log(`📄 Added ${addedCount} URLs from sitemap`);
      }
    }
  } catch (e) {
    console.log(`ℹ️  Sitemap not accessible: ${e.message}`);
  }
}

/**
 * Enhanced link discovery from current page
 */
async function discoverPageLinks(page, currentUrl, origin) {
  try {
    const links = await page.$$eval('a[href], area[href]', (elements) =>
      Array.from(elements)
        .map((el) => el.getAttribute('href'))
        .filter(Boolean)
    );

    const validLinks = [];
    for (const href of links.slice(0, 20)) { // Limit links per page
      try {
        const target = new URL(href, currentUrl);
        if (target.origin === origin && 
            !target.hash && 
            !target.pathname.match(/\.(pdf|jpg|jpeg|png|gif|zip|doc|docx|css|js)$/i) &&
            !target.search.includes('logout') &&
            !target.pathname.includes('/admin/') &&
            !target.pathname.includes('/wp-admin/')) {
          validLinks.push(target.href);
        }
      } catch (e) {
        // Invalid URL, skip
      }
    }

    return [...new Set(validLinks)];
  } catch (e) {
    console.error(`Error discovering links from ${currentUrl}:`, e.message);
    return [];
  }
}

/**
 * Enhanced analysis of scan results
 */
function analyzeResults(results) {
  let totalViolations = 0;
  const byImpact = { critical: 0, serious: 0, moderate: 0, minor: 0 };
  const violationTypes = new Set();
  
  for (const result of results) {
    for (const violation of result.violations ?? []) {
      const nodeCount = violation.nodes?.length || 1;
      totalViolations += nodeCount;
      violationTypes.add(violation.id);
      
      if (violation.impact && byImpact[violation.impact] !== undefined) {
        byImpact[violation.impact] += nodeCount;
      } else {
        // Default to moderate if impact is unknown
        byImpact.moderate += nodeCount;
      }
    }
  }

  const totalPages = results.length;
  
  // Enhanced compliance score calculation
  const violationDensity = totalViolations / Math.max(totalPages, 1);
  const uniqueViolationTypes = violationTypes.size;
  
  // Weighted scoring based on violation density and severity
  const criticalWeight = byImpact.critical * 4;
  const seriousWeight = byImpact.serious * 3;
  const moderateWeight = byImpact.moderate * 2;
  const minorWeight = byImpact.minor * 1;
  
  const weightedViolations = criticalWeight + seriousWeight + moderateWeight + minorWeight;
  const maxPossibleScore = totalPages * 100; // Assume 100 potential violations per page
  const complianceScore = Math.max(0, Math.min(100, 
    Math.round(100 - (weightedViolations / Math.max(maxPossibleScore, 1)) * 100)
  ));

  return {
    totalPages,
    totalViolations,
    byImpact,
    complianceScore,
    uniqueViolationTypes,
    violationDensity: Math.round(violationDensity * 100) / 100
  };
}
