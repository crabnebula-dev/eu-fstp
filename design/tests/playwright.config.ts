// Playwright config for the static design prototypes.
// Playwright is allowlisted as a test tool (ADR-003). It never ships.
// The prototypes are opened as file:// URLs, so no web server is needed.
import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: '.',
  testMatch: '*.spec.ts',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: 0,
  reporter: [['list']],
  // Keep run artefacts out of the design tree. Override with PW_OUTPUT_DIR.
  outputDir: process.env.PW_OUTPUT_DIR || './test-results',
  use: {
    headless: true,
    trace: 'retain-on-failure',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
  ],
});
