delete process.env.HTTP_PROXY;
delete process.env.HTTPS_PROXY;
delete process.env.http_proxy;
delete process.env.https_proxy;
delete process.env.ALL_PROXY;
delete process.env.all_proxy;
process.env.NODE_USE_ENV_PROXY = '0';

import { defineConfig } from '@playwright/test';
export default defineConfig({
  testMatch: ['tests/browser/**/*.spec.ts', 'apps/web/tests/**/*.spec.ts'],
  timeout: 30000,
  use: {
    baseURL: 'http://127.0.0.1:4173', browserName: 'chromium', headless: true,
    launchOptions: process.env.WEB_TEST_CHROMIUM ? { executablePath: process.env.WEB_TEST_CHROMIUM, args: ['--no-sandbox'] } : {},
  },
  webServer: {
    command: process.env.POLICYHELIX_INSTALLED_RELEASE ? 'node scripts/start-local.mjs --root web --engine-bin engine/policyhelix' : 'npm start',
    cwd: process.env.POLICYHELIX_INSTALLED_RELEASE, url: 'http://127.0.0.1:4173/readyz', reuseExistingServer: false, timeout: 15000 },
  reporter: 'list',
});
