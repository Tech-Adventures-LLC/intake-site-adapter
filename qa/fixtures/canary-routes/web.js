import { createCanaryHandler, createWebHandler } from '../../../packages/intake-site-adapter/index.js';

export const POST = createWebHandler(createCanaryHandler({ source: 'fixture-site', logger: null }));
