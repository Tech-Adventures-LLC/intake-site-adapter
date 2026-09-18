export interface VerificationResult {
  ok: true;
  route: string;
  style: 'web' | 'vercel';
  anonymous_status: 401;
  wrong_token_status: 401;
  authenticated_status: 200;
  source: string;
  contract_version: 'intake-contract-v1';
  adapter_version: '1.1.0';
  source_sha: string;
  environment: 'preview';
}

/** Executes trusted local JavaScript in a bounded synthetic subprocess; not an OS sandbox. */
export function verifyCanaryRoute(options: {
  routePath: string;
  source: string;
  projectRoot?: string;
  /** Integer milliseconds, 100–10000; default 5000. */
  timeoutMs?: number;
}): Promise<VerificationResult>;
