import { chromium } from 'playwright';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const axe = require('axe-core');

/**
 * PRODUCTION-READY ACCESSIBILITY SCANNER - FIXED VERSION
 * 
 * This version removes the duplicate export that was causing the syntax error.
 * All other functionality remains the same.
 */
export async function crawlAndScan(startUrl, opts = {}) {
  const maxPages = Math.min(Math.max(opts.maxPages ?? 50, 1), 200);
  const origin = new URL(startUrl).origin;

  console.log(`🔍 Starting production accessibility scan of ${startUrl} (max ${maxPages} pages)`);

  const browser = await chromium.launch({ 
    headless: true,
    args: [
      '--no-sandbox', 
      '--disable-setuid-sandbox',
      '--disable-web-security',
      '--disable-features=VizDisplayCompositor',
      '--disable-dev-shm-usage',
      '--no-first-run',
      '--disable-gpu',
      '--force-color-profile=srgb',
      '--disable-background-timer-throttling',
      '--disable-renderer-backgrounding'
    ]
  });
  
  const context = await browser.newContext({
    userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    viewport: { width: 1280, height: 720 },
    ignoreHTTPSErrors: true,
    colorScheme: 'light'
  });
  
  const page = await context.newPage();

  const queue = new Set([startUrl]);
  const seen = new Set();
  const results = [];
  const errors = [];

  try {
    // Discover additional pages via sitemap (with proper timeout)
    await discoverSitemapUrls(startUrl, queue, origin);
    
    while (queue.size && results.length < maxPages) {
      const current = queue.values().next().value;
      queue.delete(current);
      
      if (seen.has(current)) continue;
      seen.add(current);

      console.log(`📄 Scanning page ${results.length + 1}/${maxPages}: ${current}`);

      const pageResult = await productionPageScan(page, current, 3);
      
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

  // Calculate summary statistics from normalized results
  let totalViolations = 0;
  let totalAlerts = 0;
  const byImpact = { critical: 0, serious: 0, moderate: 0, minor: 0 };
  
  for (const result of results) {
    totalViolations += (result.violations || []).length;
    totalAlerts += (result.alerts || []).length;
    
    // Count by impact (from violations only, as per analysis)
    for (const violation of result.violations || []) {
      if (violation.impact && byImpact[violation.impact] !== undefined) {
        byImpact[violation.impact] += violation.nodes?.length || 1;
      } else {
        byImpact.moderate += violation.nodes?.length || 1;
      }
    }
  }

  const totalPages = results.length;
  
  // Calculate compliance score
  const violationDensity = totalViolations / Math.max(totalPages, 1);
  const criticalWeight = byImpact.critical * 4;
  const seriousWeight = byImpact.serious * 3;
  const moderateWeight = byImpact.moderate * 2;
  const minorWeight = byImpact.minor * 1;
  
  const weightedViolations = criticalWeight + seriousWeight + moderateWeight + minorWeight;
  const maxPossibleScore = totalPages * 100;
  const complianceScore = Math.max(0, Math.min(100, 
    Math.round(100 - (weightedViolations / Math.max(maxPossibleScore, 1)) * 100)
  ));
  
  console.log(`✅ Production scan completed:`);
  console.log(`   📄 Pages scanned: ${totalPages}`);
  console.log(`   🚨 Total violations: ${totalViolations}`);
  console.log(`   ⚠️  Total alerts: ${totalAlerts}`);
  console.log(`   📊 By impact: Critical(${byImpact.critical}) Serious(${byImpact.serious}) Moderate(${byImpact.moderate}) Minor(${byImpact.minor})`);
  console.log(`   📈 Compliance score: ${complianceScore}%`);
  console.log(`   ❌ Failed pages: ${errors.length}`);

  return {
    startUrl,
    scannedAt: new Date().toISOString(),
    totalPages,
    totalViolations,
    byImpact,
    complianceScore,
    pages: results,
    errors: errors.length > 0 ? errors : undefined,
    scannerVersion: 'production-ready-v1.0'
  };
}

/**
 * Production page scanning with all fixes applied
 */
async function productionPageScan(page, url, maxRetries = 3) {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      await page.goto(url, { 
        waitUntil: 'networkidle',
        timeout: 60000
      });

      // Enhanced dynamic content loading
      console.log(`   ⏳ Waiting for dynamic content...`);
      await page.waitForTimeout(4000);
      
      // Wait for loading indicators
      try {
        await page.waitForFunction(() => {
          const loadingSelectors = [
            '[data-loading="true"]', '.loading', '.spinner', '[aria-busy="true"]',
            '.loader', '.loading-spinner', '.preloader', '[data-testid*="loading"]'
          ];
          return !loadingSelectors.some(sel => document.querySelector(sel));
        }, { timeout: 5000 });
      } catch (e) {}
      
      // Trigger lazy loading
      await page.evaluate(() => {
        window.scrollTo(0, document.body.scrollHeight / 2);
      });
      await page.waitForTimeout(1000);
      await page.evaluate(() => {
        window.scrollTo(0, 0);
      });
      await page.waitForTimeout(2000);

      // Inject axe-core
      await page.addScriptTag({ content: axe.source });

      console.log(`   🔍 Running production detection...`);

      // STEP 1: Run axe-core with proper rule selection
      const axeResults = await page.evaluate(async () => {
        try {
          const result = await window.axe.run(document, {
            runOnly: { 
              type: 'tag', 
              values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'best-practice'] 
            },
            resultTypes: ['violations', 'incomplete'],
            reporter: 'v2'
          });
          
          return result;
        } catch (axeError) {
          console.error('Axe-core scan failed:', axeError);
          return { violations: [], incomplete: [] };
        }
      });

      // STEP 2: Enhanced contrast detection with ancestor background inheritance
      const contrastViolations = await page.evaluate(() => {
        function parse(c) {
          const m = c && c.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)(?:,\s*([0-9.]+))?\)/i);
          if (!m) return null;
          return { r: +m[1] / 255, g: +m[2] / 255, b: +m[3] / 255, a: m[4] ? +m[4] : 1 };
        }
        
        function lin(v) {
          return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
        }
        
        function lum({ r, g, b }) {
          r = lin(r); g = lin(g); b = lin(b);
          return 0.2126 * r + 0.7152 * g + 0.0722 * b;
        }
        
        function contrast(f, b) {
          const L1 = Math.max(lum(f), lum(b));
          const L2 = Math.min(lum(f), lum(b));
          return (L1 + 0.05) / (L2 + 0.05);
        }
        
        function isTransparent(c) {
          return !c || c.a === 0;
        }
        
        function effectiveBg(el) {
          let n = el;
          while (n && n !== document.documentElement) {
            const cs = getComputedStyle(n);
            const bg = parse(cs.backgroundColor);
            if (bg && !isTransparent(bg)) return bg;
            n = n.parentElement;
          }
          const body = parse(getComputedStyle(document.body).backgroundColor);
          if (body && !isTransparent(body)) return body;
          const root = parse(getComputedStyle(document.documentElement).backgroundColor);
          return root || { r: 1, g: 1, b: 1, a: 1 };
        }
        
        function visible(el) {
          const cs = getComputedStyle(el);
          if (cs.visibility === 'hidden' || cs.display === 'none' || +cs.opacity === 0) return false;
          const r = el.getBoundingClientRect();
          return r.width > 0 && r.height > 0;
        }
        
        function largeText(el) {
          const cs = getComputedStyle(el);
          const size = parseFloat(cs.fontSize);
          const bold = ((+cs.fontWeight) || 400) >= 700;
          return size >= 24 || (size >= 18.66 && bold) || (size >= 18 && bold);
        }
        
        function cssPath(el) {
          if (el.id) return '#' + el.id;
          const parts = [];
          while (el && el.nodeType === 1 && parts.length < 4) {
            let sel = el.nodeName.toLowerCase();
            if (el.classList.length) sel += '.' + [...el.classList].slice(0, 2).join('.');
            parts.unshift(sel);
            el = el.parentElement;
          }
          return parts.join('>');
        }

        const findings = [];
        const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_ELEMENT, {
          acceptNode(el) {
            if (!visible(el)) return NodeFilter.FILTER_SKIP;
            const text = (el.innerText || '').trim();
            if (!text) return NodeFilter.FILTER_SKIP;
            const tag = el.tagName.toLowerCase();
            const candidates = ['p', 'span', 'a', 'li', 'button', 'label', 'input', 'textarea', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'th', 'td', 'div'];
            return candidates.includes(tag) ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_SKIP;
          }
        });
        
        let el;
        while (el = walker.nextNode()) {
          const cs = getComputedStyle(el);
          const fg = parse(cs.color);
          if (!fg) continue;
          const bg = effectiveBg(el);
          const ratio = contrast(fg, bg);
          const thresh = largeText(el) ? 3.0 : 4.5;
          if (Number.isFinite(ratio) && ratio < thresh) {
            findings.push({
              id: 'color-contrast',
              impact: 'serious',
              description: `Text/background contrast ${ratio.toFixed(2)}:1 below ${thresh}:1`,
              help: 'Elements must have sufficient color contrast',
              helpUrl: 'https://www.w3.org/WAI/WCAG21/Understanding/contrast-minimum.html',
              nodes: [{ target: [cssPath(el)], html: el.outerHTML.slice(0, 300) }]
            });
          }
        }
        return findings;
      });

      // STEP 3: Heuristic-based alert detection
      const alertViolations = await page.evaluate(() => {
        const alerts = [];
        
        function cssPath(el, index) {
          if (el.id) return '#' + el.id;
          if (el.className && typeof el.className === 'string') {
            const classes = el.className.split(' ').filter(c => c.trim());
            if (classes.length > 0) return '.' + classes[0];
          }
          return el.tagName.toLowerCase() + ':nth-of-type(' + (index + 1) + ')';
        }
        
        // Alert 1: Images without alt text
        document.querySelectorAll('img').forEach((img, index) => {
          if (!img.alt) {
            alerts.push({
              id: 'alert-image-alt-missing',
              impact: 'moderate',
              description: 'Image missing alt attribute (potential accessibility issue)',
              help: 'Images should have alternative text',
              helpUrl: 'https://www.w3.org/WAI/WCAG21/Understanding/images-of-text.html',
              nodes: [{ target: [cssPath(img, index)], html: img.outerHTML.substring(0, 200) }]
            });
          }
        });
        
        // Alert 2: Links with generic text
        document.querySelectorAll('a').forEach((link, index) => {
          const text = link.textContent.trim().toLowerCase();
          const genericTexts = ['click here', 'read more', 'more', 'here', 'link', 'continue'];
          if (genericTexts.includes(text)) {
            alerts.push({
              id: 'alert-generic-link-text',
              impact: 'moderate',
              description: 'Link has generic text that may not be descriptive',
              help: 'Links should have descriptive text',
              helpUrl: 'https://www.w3.org/WAI/WCAG21/Understanding/link-purpose-in-context.html',
              nodes: [{ target: [cssPath(link, index)], html: link.outerHTML.substring(0, 200) }]
            });
          }
        });
        
        // Alert 3: Small click targets
        document.querySelectorAll('a, button, input[type="button"], input[type="submit"]').forEach((element, index) => {
          const rect = element.getBoundingClientRect();
          const minSize = 44;
          
          if (rect.width > 0 && rect.height > 0 && (rect.width < minSize || rect.height < minSize)) {
            alerts.push({
              id: 'alert-small-click-target',
              impact: 'moderate',
              description: `Click target is ${Math.round(rect.width)}x${Math.round(rect.height)}px (should be at least ${minSize}x${minSize}px)`,
              help: 'Click targets should be at least 44x44 pixels',
              helpUrl: 'https://www.w3.org/WAI/WCAG21/Understanding/target-size.html',
              nodes: [{ target: [cssPath(element, index)], html: element.outerHTML.substring(0, 200) }]
            });
          }
        });
        
        return alerts;
      });

      // STEP 4: Manual accessibility checks
      const manualViolations = await page.evaluate(() => {
        const violations = [];
        
        // Check for missing page title
        if (!document.title || document.title.trim().length === 0) {
          violations.push({
            id: 'manual-missing-title',
            impact: 'serious',
            description: 'Page is missing a title',
            help: 'Pages should have a descriptive title',
            helpUrl: 'https://www.w3.org/WAI/WCAG21/Understanding/page-titled.html',
            nodes: [{ target: ['html'], html: '<title></title>' }]
          });
        }
        
        // Check for missing lang attribute
        if (!document.documentElement.lang) {
          violations.push({
            id: 'manual-missing-lang',
            impact: 'serious',
            description: 'Page is missing lang attribute',
            help: 'Pages should specify their language',
            helpUrl: 'https://www.w3.org/WAI/WCAG21/Understanding/language-of-page.html',
            nodes: [{ target: ['html'], html: document.documentElement.outerHTML.substring(0, 200) }]
          });
        }
        
        return violations;
      });

      // STEP 5: Complete iframe scanning (violations + incomplete as alerts)
      let iframeViolations = [];
      let iframeIncomplete = [];
      try {
        const frames = page.frames();
        for (const frame of frames) {
          if (frame !== page.mainFrame()) {
            try {
              const frameUrl = frame.url();
              if (frameUrl && frameUrl.startsWith(new URL(url).origin)) {
                await frame.addScriptTag({ content: axe.source });
                const frameResults = await frame.evaluate(async () => {
                  try {
                    return await window.axe.run(document, {
                      runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'best-practice'] },
                      resultTypes: ['violations', 'incomplete'],
                      reporter: 'v2'
                    });
                  } catch { 
                    return { violations: [], incomplete: [] }; 
                  }
                });
                iframeViolations = iframeViolations.concat(frameResults.violations || []);
                iframeIncomplete = iframeIncomplete.concat(frameResults.incomplete || []);
              }
            } catch (e) {
              // Skip iframes that can't be accessed
            }
          }
        }
      } catch (e) {
        // Skip iframe scanning if it fails
      }

      // NORMALIZE RESULTS TO EXPECTED SHAPE with improved deduplication
      const normalizedViolations = normalizeViolations(
        axeResults.violations || [],
        contrastViolations,
        manualViolations,
        iframeViolations
      );
      
      const normalizedAlerts = normalizeAlerts(
        axeResults.incomplete || [],
        alertViolations,
        iframeIncomplete
      );

      const totalViolationInstances = normalizedViolations.reduce((sum, v) => sum + (v.nodes?.length || 1), 0);
      const totalAlertInstances = normalizedAlerts.reduce((sum, a) => sum + (a.nodes?.length || 1), 0);

      console.log(`   🚨 Found ${normalizedViolations.length} violation types (${totalViolationInstances} instances)`);
      console.log(`   ⚠️  Found ${normalizedAlerts.length} alert types (${totalAlertInstances} instances)`);
      console.log(`   📊 Total issues: ${totalViolationInstances + totalAlertInstances}`);

      return {
        success: true,
        data: {
          url,
          violations: normalizedViolations,  // ✅ Expected shape
          alerts: normalizedAlerts,          // ✅ Expected shape
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
      
      await new Promise(resolve => setTimeout(resolve, attempt * 3000));
    }
  }
}

// Helper functions for result normalization with improved deduplication
function normalizeTargetString(t) {
  if (Array.isArray(t)) t = t.join(' ');
  if (!t) return '';
  // Collapse whitespace + strip nth-child noise to reduce false mismatches
  return t.replace(/\s+/g, ' ').replace(/:nth-of-type\(\d+\)/ig, '').trim();
}

function toNodes(nodes = []) {
  return nodes.map(n => ({
    target: Array.isArray(n.target) ? n.target.join(' ') : n.target,
    failureSummary: n.failureSummary || '',
    html: typeof n.html === 'string' ? n.html.slice(0, 500) : ''
  }));
}

function normalizeViolations(axeViolations = [], contrastViolations = [], manualViolations = [], iframeViolations = []) {
  const all = [];
  
  // Add axe violations
  for (const v of axeViolations) {
    all.push({
      id: v.id,
      impact: v.impact || 'moderate',
      description: v.description,
      help: v.help,
      helpUrl: v.helpUrl,
      nodes: toNodes(v.nodes)
    });
  }
  
  // Add custom contrast violations with improved deduplication
  const existingContrastTargets = new Set();
  for (const v of axeViolations) {
    if (v.id === 'color-contrast') {
      for (const node of v.nodes || []) {
        existingContrastTargets.add(normalizeTargetString(node.target));
      }
    }
  }
  
  for (const c of contrastViolations) {
    const target = normalizeTargetString(c.nodes?.[0]?.target);
    if (!existingContrastTargets.has(target)) {
      all.push({
        id: c.id,
        impact: c.impact || 'serious',
        description: c.description,
        help: c.help,
        helpUrl: c.helpUrl,
        nodes: toNodes(c.nodes)
      });
    }
  }
  
  // Add manual violations
  for (const m of manualViolations) {
    all.push({
      id: m.id,
      impact: m.impact || 'serious',
      description: m.description,
      help: m.help || 'Manual check',
      helpUrl: m.helpUrl || '',
      nodes: toNodes(m.nodes)
    });
  }
  
  // Add iframe violations
  for (const i of iframeViolations) {
    all.push({
      id: i.id + '_iframe',
      impact: i.impact || 'moderate',
      description: i.description + ' (in iframe)',
      help: i.help,
      helpUrl: i.helpUrl,
      nodes: toNodes(i.nodes)
    });
  }
  
  return all;
}

function normalizeAlerts(axeIncomplete = [], alertViolations = [], iframeIncomplete = []) {
  const all = [];
  
  // Add axe incomplete as alerts
  for (const v of axeIncomplete) {
    all.push({
      id: v.id,
      impact: v.impact || 'unknown',
      description: v.description,
      help: v.help,
      helpUrl: v.helpUrl,
      nodes: toNodes(v.nodes)
    });
  }
  
  // Add heuristic alerts
  for (const a of alertViolations) {
    all.push({
      id: a.id,
      impact: a.impact || 'moderate',
      description: a.description,
      help: a.help || 'Heuristic (needs review)',
      helpUrl: a.helpUrl || '',
      nodes: toNodes(a.nodes)
    });
  }
  
  // Add iframe incomplete as alerts
  for (const i of iframeIncomplete) {
    all.push({
      id: i.id + '_iframe_incomplete',
      impact: i.impact || 'unknown',
      description: i.description + ' (in iframe, needs review)',
      help: i.help,
      helpUrl: i.helpUrl,
      nodes: toNodes(i.nodes)
    });
  }
  
  return all;
}

/**
 * Discover URLs from sitemap.xml with proper timeout handling
 */
async function discoverSitemapUrls(startUrl, queue, origin) {
  try {
    const sitemapUrl = `${origin}/sitemap.xml`;
    console.log(`🗺️  Checking sitemap: ${sitemapUrl}`);
    
    // Use AbortController for proper timeout (Node.js fetch ignores timeout option)
    const ac = new AbortController();
    const timeout = setTimeout(() => ac.abort(), 10000);
    
    const response = await fetch(sitemapUrl, { signal: ac.signal }).catch(() => null);
    clearTimeout(timeout);
    
    if (response && response.ok) {
      const sitemapText = await response.text();
      const urlMatches = sitemapText.match(/<loc>(.*?)<\/loc>/g);
      
      if (urlMatches) {
        let addedCount = 0;
        for (const match of urlMatches.slice(0, 20)) {
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
 * Enhanced link discovery
 */
async function discoverPageLinks(page, currentUrl, origin) {
  try {
    const links = await page.$$eval('a[href], area[href]', (elements) =>
      Array.from(elements)
        .map((el) => el.getAttribute('href'))
        .filter(Boolean)
    );

    const validLinks = [];
    for (const href of links.slice(0, 10)) {
      try {
        const target = new URL(href, currentUrl);
        if (target.origin === origin && 
            !target.hash && 
            !target.pathname.match(/\.(pdf|jpg|jpeg|png|gif|zip|doc|docx|css|js)$/i) &&
            !target.search.includes('logout') &&
            !target.pathname.includes('/admin/')) {
          validLinks.push(target.href);
        }
      } catch (e) {}
    }

    return [...new Set(validLinks)];
  } catch (e) {
    console.error(`Error discovering links from ${currentUrl}:`, e.message);
    return [];
  }
}
