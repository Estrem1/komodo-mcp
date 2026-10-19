/** Narrow process-owned adapter around Komodo's official client. */

import { readFileSync } from "node:fs";
import type { Types } from "komodo_client";
import pLimit from "p-limit";
import { Agent, type Dispatcher, getGlobalDispatcher, setGlobalDispatcher } from "undici";

// komodo_client 2.1.1 eagerly loads its browser auth dependency, which reads
// localStorage even for API-key clients. Node 25 exposes a localStorage global
// without Web Storage methods unless it is configured with --localstorage-file,
// so verify the interface rather than only checking that the name exists.
const localStorageDescriptor = Object.getOwnPropertyDescriptor(globalThis, "localStorage");
const existingLocalStorage =
  localStorageDescriptor && "value" in localStorageDescriptor
    ? localStorageDescriptor.value
    : undefined;
if (
  typeof existingLocalStorage?.getItem !== "function" ||
  typeof existingLocalStorage.setItem !== "function"
) {
  const values = new Map<string, string>();
  Object.defineProperty(globalThis, "localStorage", {
    configurable: true,
    value: {
      get length() {
        return values.size;
      },
      clear: () => values.clear(),
      getItem: (key: string) => values.get(String(key)) ?? null,
      key: (index: number) => [...values.keys()][index] ?? null,
      removeItem: (key: string) => values.delete(String(key)),
      setItem: (key: string, value: string) => values.set(String(key), String(value)),
    },
  });
}

const { KomodoClient: createOfficialClient } = await import("komodo_client");

type Endpoint = "read" | "write" | "execute";

export type OperationFor<E extends Endpoint> = E extends "read"
  ? Types.ReadRequest["type"]
  : E extends "write"
    ? Types.WriteRequest["type"]
    : Types.ExecuteRequest["type"];

export interface KomodoConfig {
  address: string;
  apiKey: string;
  apiSecret: string;
  /** Absolute request deadline in milliseconds. Defaults to 30 seconds. */
  timeoutMs?: number;
  /** Maximum number of concurrent in-flight requests. Defaults to 8. */
  maxConcurrency?: number;
  /** Maximum response body size in bytes. Defaults to 16 MiB. */
  maxResponseBytes?: number;
}

type OfficialClient = ReturnType<typeof createOfficialClient>;

const dispatcherLinks = new Map<Dispatcher, { prior: Dispatcher }>();

function readEnvOrFile(envName: string): string | undefined {
  const direct = process.env[envName];
  if (direct && direct.length > 0) return direct;

  const filePath = process.env[`${envName}_FILE`];
  if (filePath && filePath.length > 0) {
    try {
      return readFileSync(filePath, "utf8").trim();
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      throw new Error(
        `Failed to read ${envName}_FILE: check that the file exists and is readable${code ? ` (${code})` : ""}`
      );
    }
  }
  return undefined;
}

function normalizeAddress(raw: string): string {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error("KOMODO_ADDRESS is not a valid URL: expected http:// or https://");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("KOMODO_ADDRESS must be http:// or https://");
  }
  return parsed.origin;
}

function positiveInteger(value: number | undefined, fallback: number, name: string): number {
  const candidate = value ?? fallback;
  if (!Number.isInteger(candidate) || candidate < 1) {
    throw new Error(`Invalid ${name}: expected a positive integer`);
  }
  return candidate;
}

function readNumberEnv(name: string): number | undefined {
  const raw = process.env[name];
  if (!raw) return undefined;
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed < 1) {
    throw new Error(`Invalid ${name}: expected a positive integer`);
  }
  return parsed;
}

function safeString(value: unknown): string {
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function errorDetail(error: unknown): string {
  if (error instanceof Error) {
    const cause = (error as Error & { cause?: unknown }).cause;
    return cause === undefined ? error.message : `${error.message}: ${errorDetail(cause)}`;
  }
  if (error && typeof error === "object") {
    const rejection = error as { error?: unknown; result?: unknown };
    if (rejection.error !== undefined && rejection.error !== error) {
      return errorDetail(rejection.error);
    }
    if (rejection.result !== undefined) return safeString(rejection.result);
  }
  return safeString(error);
}

// ---------- log sanitization ----------

/** Env names whose values must never reach a log sink in clear text. */
const LOG_SECRET_ENV_NAMES = ["KOMODO_API_KEY", "KOMODO_API_SECRET", "MCP_AUTH_TOKEN"] as const;

/**
 * Build a logger-safe representation of an arbitrary thrown value: name,
 * message and stack only — no enumerable custom properties and no `cause`
 * chain — with every known secret value replaced by "[redacted]". Log sinks
 * for top-level failures (e.g. the fatal-error handler) must route errors
 * through this helper so environment-sourced secrets cannot reach stderr in
 * clear text.
 */
export function sanitizeErrorForLog(
  error: unknown,
  extraSecrets: readonly (string | undefined)[] = []
): { name: string; message: string; stack?: string } {
  const secrets = new Set<string>();
  for (const name of LOG_SECRET_ENV_NAMES) {
    const value = process.env[name];
    if (value && value.length >= 4) secrets.add(value);
  }
  for (const value of extraSecrets) {
    if (value && value.length >= 4) secrets.add(value);
  }
  const redact = (text: string): string => {
    let output = text;
    for (const secret of secrets) {
      output = output.split(secret).join("[redacted]");
    }
    return output;
  };
  if (error instanceof Error) {
    const sanitized: { name: string; message: string; stack?: string } = {
      name: error.name,
      message: redact(error.message),
    };
    if (error.stack !== undefined) sanitized.stack = redact(error.stack);
    return sanitized;
  }
  return { name: typeof error, message: redact(safeString(error)) };
}

function deadlineInterceptor(timeoutMs: number): Dispatcher.DispatcherComposeInterceptor {
  return (dispatch) => (options, handler) => {
    let timeout: NodeJS.Timeout | undefined;
    const clearDeadline = () => {
      if (timeout) clearTimeout(timeout);
      timeout = undefined;
    };
    const wrapped: Dispatcher.DispatchHandler = {
      onRequestStart(controller, context) {
        timeout = setTimeout(() => {
          controller.abort(
            new DOMException(`Request timed out after ${timeoutMs}ms`, "TimeoutError")
          );
        }, timeoutMs);
        timeout.unref();
        handler.onRequestStart?.call(handler, controller, context);
      },
      onRequestUpgrade(controller, statusCode, headers, socket) {
        clearDeadline();
        handler.onRequestUpgrade?.call(handler, controller, statusCode, headers, socket);
      },
      onResponseStart(controller, statusCode, headers, statusMessage) {
        handler.onResponseStart?.call(handler, controller, statusCode, headers, statusMessage);
      },
      onResponseData(controller, chunk) {
        handler.onResponseData?.call(handler, controller, chunk);
      },
      onResponseEnd(controller, trailers) {
        clearDeadline();
        handler.onResponseEnd?.call(handler, controller, trailers);
      },
      onResponseError(controller, error) {
        clearDeadline();
        handler.onResponseError?.call(handler, controller, error);
      },
      onResponseStarted() {
        handler.onResponseStarted?.call(handler);
      },
      onBodySent(chunk) {
        handler.onBodySent?.call(handler, chunk);
      },
      onRequestSent() {
        handler.onRequestSent?.call(handler);
      },
    };
    return dispatch(
      {
        ...options,
        headersTimeout: timeoutMs,
        bodyTimeout: timeoutMs,
      },
      wrapped
    );
  };
}

export class KomodoClient {
  readonly address: string;
  readonly timeoutMs: number;
  readonly maxConcurrency: number;
  readonly maxResponseBytes: number;

  #apiKey: string;
  #apiSecret: string;
  #official: OfficialClient;
  #limit: ReturnType<typeof pLimit>;
  #agent: Agent;
  #dispatcher: Dispatcher;
  #closed = false;

  constructor(config: KomodoConfig) {
    this.address = normalizeAddress(config.address);
    this.timeoutMs = positiveInteger(config.timeoutMs, 30_000, "timeoutMs");
    this.maxConcurrency = positiveInteger(config.maxConcurrency, 8, "maxConcurrency");
    this.maxResponseBytes = positiveInteger(
      config.maxResponseBytes,
      16 * 1024 * 1024,
      "maxResponseBytes"
    );
    this.#apiKey = config.apiKey;
    this.#apiSecret = config.apiSecret;
    this.#limit = pLimit(this.maxConcurrency);

    this.#agent = new Agent({
      connections: 16,
      pipelining: 1,
      keepAliveTimeout: 30_000,
      keepAliveMaxTimeout: 60_000,
      headersTimeout: this.timeoutMs,
      bodyTimeout: this.timeoutMs,
      maxResponseSize: this.maxResponseBytes,
    });
    this.#dispatcher = this.#agent.compose(deadlineInterceptor(this.timeoutMs));
    dispatcherLinks.set(this.#dispatcher, { prior: getGlobalDispatcher() });
    setGlobalDispatcher(this.#dispatcher);

    this.#official = createOfficialClient(this.address, {
      type: "api-key",
      params: { key: this.#apiKey, secret: this.#apiSecret },
    });
  }

  static fromEnv(): KomodoClient {
    const address = readEnvOrFile("KOMODO_ADDRESS");
    const apiKey = readEnvOrFile("KOMODO_API_KEY");
    const apiSecret = readEnvOrFile("KOMODO_API_SECRET");

    if (!address || !apiKey || !apiSecret) {
      throw new Error(
        "Missing required environment variables: KOMODO_ADDRESS, KOMODO_API_KEY, KOMODO_API_SECRET"
      );
    }

    const timeoutMs = readNumberEnv("KOMODO_TIMEOUT_MS");
    const maxConcurrency = readNumberEnv("KOMODO_MAX_CONCURRENCY");
    const maxResponseBytes = readNumberEnv("KOMODO_MAX_RESPONSE_BYTES");
    return new KomodoClient({
      address,
      apiKey,
      apiSecret,
      ...(timeoutMs !== undefined ? { timeoutMs } : {}),
      ...(maxConcurrency !== undefined ? { maxConcurrency } : {}),
      ...(maxResponseBytes !== undefined ? { maxResponseBytes } : {}),
    });
  }

  async call<E extends Endpoint>(
    endpoint: E,
    operation: OperationFor<E>,
    params: Record<string, unknown> = {}
  ): Promise<unknown> {
    return this.#limit(async () => {
      try {
        if (endpoint === "read") {
          return await this.#official.read(operation as never, params as never);
        }
        if (endpoint === "write") {
          return await this.#official.write(operation as never, params as never);
        }
        return await this.#official.execute(operation as never, params as never);
      } catch (error) {
        const detail = this.#redact(errorDetail(error));
        throw new Error(`Komodo API ${endpoint} (${operation}) request failed: ${detail}`);
      }
    });
  }

  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    const link = dispatcherLinks.get(this.#dispatcher);
    if (link) {
      for (const other of dispatcherLinks.values()) {
        if (other.prior === this.#dispatcher) other.prior = link.prior;
      }
      if (getGlobalDispatcher() === this.#dispatcher) {
        setGlobalDispatcher(link.prior);
      }
      dispatcherLinks.delete(this.#dispatcher);
    }
    await this.#agent.close();
  }

  toJSON(): Record<string, unknown> {
    return {
      address: this.address,
      apiKey: "[redacted]",
      apiSecret: "[redacted]",
      timeoutMs: this.timeoutMs,
      maxConcurrency: this.maxConcurrency,
      maxResponseBytes: this.maxResponseBytes,
    };
  }

  [Symbol.for("nodejs.util.inspect.custom")](): unknown {
    return this.toJSON();
  }

  #redact(value: string): string {
    let output = value;
    if (this.#apiSecret.length >= 4) {
      output = output.split(this.#apiSecret).join("[redacted]");
    }
    if (this.#apiKey.length >= 4) {
      output = output.split(this.#apiKey).join("[redacted]");
    }
    return output;
  }
}
