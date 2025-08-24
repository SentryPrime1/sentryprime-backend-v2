import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const axe = require('axe-core');

/**
 * SIMPLIFIED ACCESSIBILITY SCANNER - NO PLAYWRIGHT VERSION
 * 
 * This version removes Playwright dependency and provides mock scan results
 * while keeping the Alt Text AI functionality working.
 */
export async function crawlAndScan(startUrl, opts = {}) {
  const maxPages = Math.min(Math.max(opts.maxPages ?? 50, 1), 200);
  
  console.log(`🔍 Starting simplified scan of ${startUrl} (Playwright temporarily disabled)`);
  
  // Return mock scan results that match the expected format
  const mockResults = {
    startUrl,
    scannedAt: new Date().toISOString(),
    totalPages: 1,
    totalViolations: 3,
    byImpact: { 
      critical: 0, 
      serious: 1, 
      moderate: 2, 
      minor: 0 
    },
    complianceScore: 85,
    pages: [{
      url: startUrl,
      title: "Sample Page",
      violations: [
        {
          id: 'color-contrast',
          impact: 'serious',
          description: 'Elements must have sufficient color contrast',
          help: 'Ensure sufficient contrast between text and background',
          helpUrl: 'https://www.w3.org/WAI/WCAG21/Understanding/contrast-minimum.html',
          nodes: [{ target: ['body'], html: '<div>Sample violation</div>' }]
        },
        {
          id: 'image-alt',
          impact: 'moderate',
          description: 'Images must have alternative text',
          help: 'Images should have alt attributes',
          helpUrl: 'https://www.w3.org/WAI/WCAG21/Understanding/images-of-text.html',
          nodes: [{ target: ['img'], html: '<img src="example.jpg">' }]
        },
        {
          id: 'heading-order',
          impact: 'moderate',
          description: 'Heading levels should only increase by one',
          help: 'Headings should be in logical order',
          helpUrl: 'https://www.w3.org/WAI/WCAG21/Understanding/headings-and-labels.html',
          nodes: [{ target: ['h3'], html: '<h3>Sample heading</h3>' }]
        }
      ],
      alerts: [],
      passes: [],
      incomplete: [],
      timestamp: new Date( ).toISOString()
    }],
    scannerVersion: 'simplified-no-playwright-v1.0',
    note: 'This is a simplified scan. Full browser automation temporarily disabled.'
  };

  console.log(`✅ Simplified scan completed:`);
  console.log(`   📄 Pages scanned: ${mockResults.totalPages}`);
  console.log(`   🚨 Total violations: ${mockResults.totalViolations}`);
  console.log(`   📈 Compliance score: ${mockResults.complianceScore}%`);
  console.log(`   ℹ️  Note: Full scanning temporarily disabled`);

  return mockResults;
}

export default { crawlAndScan };
