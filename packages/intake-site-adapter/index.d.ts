export const ADAPTER_VERSION: '1.1.0';
export const CONTRACT_VERSION: 'intake-contract-v1';

export class SiteAdapterConfigurationError extends Error {}

type Primitive = string | number | boolean | null;
type FormInput = Record<string, unknown>;
type Selector = string | { literal: string | boolean };
type FieldMap<Fields extends string> = Partial<Record<Fields, Selector>>;

export interface IntakeHandlerOptions {
  formMap: {
    contact?: FieldMap<'name' | 'email' | 'phone'>;
    details?: FieldMap<'company' | 'location' | 'project_type' | 'timeline' | 'show_name' | 'booth_size' | 'postal_code' | 'vehicle_year' | 'vehicle_make_model' | 'vehicle_type' | 'tint_coverage' | 'windshield' | 'tint_removal' | 'service_location' | 'preferred_shade' | 'estimated_duration' | 'notes' | 'message'>;
    attribution?: FieldMap<'source' | 'medium' | 'campaign' | 'term' | 'content' | 'page' | 'landing_page' | 'referrer' | 'utm_source' | 'utm_medium' | 'utm_campaign' | 'utm_term' | 'utm_content' | 'first_touch_at' | 'last_source' | 'last_medium' | 'last_campaign' | 'last_term' | 'last_content' | 'last_landing_page' | 'last_referrer' | 'last_touch_at' | 'click_id_type' | 'click_id' | 'ga_client_id' | 'ga_session_id' | 'tracking_id' | 'navigation_path'>;
    consent?: FieldMap<'contact_request' | 'phone_contact' | 'sms' | 'disclosure_version'>;
  };
  turnstile: { action: string; allowedHostnames: string[] };
  honeypotField?: string;
  fetchImpl?: typeof fetch;
  sleep?: (milliseconds: number) => Promise<void>;
  clock?: () => number;
  logger?: { info?: (event: Record<string, Primitive | undefined>) => void } | null;
}

export interface NodeRequestLike {
  method?: string;
  headers?: Headers | Record<string, string | string[] | undefined>;
  body?: FormInput | string | Uint8Array | ReadableStream<Uint8Array>;
  [Symbol.asyncIterator]?(): AsyncIterator<Uint8Array | string>;
}

export interface NodeResponseLike {
  setHeader?(name: string, value: string): unknown;
  status(code: number): NodeResponseLike;
  json(body: unknown): unknown;
}

export type NodeHandler = (request: NodeRequestLike, response: NodeResponseLike) => Promise<unknown>;

export function createIntakeHandler(options: IntakeHandlerOptions): NodeHandler;
export function createCanaryHandler(options: {
  source: string;
  fetchImpl?: typeof fetch;
  sleep?: (milliseconds: number) => Promise<void>;
  logger?: { info?: (event: Record<string, Primitive | undefined>) => void } | null;
}): NodeHandler;
export function createWebHandler(handler: NodeHandler): (request: Request) => Promise<Response>;
export function verifyCanaryHandler(handler: NodeHandler, options?: { probeToken?: string }): Promise<{
  ok: boolean;
  unauthorized: number;
  authorized: number;
}>;
