#!/usr/bin/env node

/**
 * Komodo MCP Server entry point.
 *
 * Supports three transports:
 *   - streamable (default): MCP Streamable HTTP on `/mcp`. Single endpoint
 *     handling POST + optional SSE upstream + DELETE for session close.
 *   - sse (legacy): two-endpoint SSE transport on `/sse` and `/messages`.
 *   - stdio: pipe-based transport for local CLI usage (no HTTP server).
 *
 * The HTTP server is fronted by:
 *   - helmet (security headers)
 *   - cors (configured via MCP_ALLOWED_ORIGINS)
 *   - validateOriginAndHost (DNS-rebinding defense — strict allow-list, defense
 *     in depth on top of CORS)
 *   - requireAuth (constant-time bearer-token compare, with loopback-only
 *     fallback when no token is configured)
 *   - pino-http (structured request logging with header redaction)
 *
 * All session state is per-connection: each new SSE/Streamable session
 * instantiates its own `McpServer` so concurrent clients can never bleed state.
 */

import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import type { Server as HttpServer } from "node:http";

import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import cors from "cors";
import express, { type Express, type NextFunction, type Request, type Response } from "express";
import helmet from "helmet";
import pino from "pino";
import { pinoHttp } from "pino-http";

import { KomodoClient, sanitizeErrorForLog } from "./komodo-client.js";
import { createServer } from "./server.js";

// ---------- env parsing ----------

const env = process.env;

function readEnvOrFile(name: string): string | undefined {
  const direct = env[name];
  if (direct && direct.length > 0) return direct;
  const filePath = env[`${name}_FILE`];
  if (filePath && filePath.length > 0) {
    try {
      return readFileSync(filePath, "utf8").trim();
    } catch (err) {
      const code = err instanceof Error ? (err as NodeJS.ErrnoException).code : undefined;
      throw new Error(
        `Failed to read ${name}_FILE: check that the file exists and is readable${code ? ` (${code})` : ""}`
      );
    }
  }
  return undefined;
}

const portRaw = env["MCP_PORT"] ?? "3113";
const portParsed = Number.parseInt(portRaw, 10);
if (!Number.isInteger(portParsed) || portParsed < 1 || portParsed > 65535) {
  console.error(`Invalid MCP_PORT: ${portRaw}`);
  process.exit(1);
}
const PORT = portParsed;

const TRANSPORT = (env["MCP_TRANSPORT"] ?? "streamable") as "streamable" | "sse" | "stdio";
if (TRANSPORT !== "streamable" && TRANSPORT !== "sse" && TRANSPORT !== "stdio") {
  console.error(`Invalid MCP_TRANSPORT: ${TRANSPORT} (expected "streamable", "sse", or "stdio")`);
  process.exit(1);
}

const BIND_HOST = env["MCP_BIND_HOST"] ?? "127.0.0.1";
const AUTH_TOKEN = readEnvOrFile("MCP_AUTH_TOKEN");
const ALLOWED_ORIGINS = (env["MCP_ALLOWED_ORIGINS"] ?? "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
const ALLOWED_HOSTS = (env["MCP_ALLOWED_HOSTS"] ?? "127.0.0.1,localhost")
  .split(",")
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);

// ---------- logger ----------
// Always write to stderr — keeps stdio transport's stdout channel clean and is
// fine for Docker (Docker captures both streams).
export const logger = pino(
  {
    level: env["LOG_LEVEL"] ?? "info",
    redact: {
      paths: [
        'req.headers["authorization"]',
        'req.headers["x-api-key"]',
        'req.headers["x-api-secret"]',
        'res.headers["set-cookie"]',
      ],
      censor: "[redacted]",
    },
  },
  pino.destination(2)
);

// ---------- auth & origin/host middleware ----------

/**
 * Compare two strings in constant time using SHA-256 digests of fixed length.
 * Hashing first prevents leaking the token's length via the early-return path
 * a naive byte compare would take when the lengths differ.
 */
function constantTimeEqual(a: string, b: string): boolean {
  const ha = createHash("sha256").update(a).digest();
  const hb = createHash("sha256").update(b).digest();
  return timingSafeEqual(ha, hb);
}

/**
 * Bearer-token auth gate. If no `MCP_AUTH_TOKEN` is configured, only loopback
 * IPs are admitted — this keeps `npm start` ergonomic for local dev while
 * refusing any non-loopback access until the operator explicitly opts in by
 * setting a token.
 */
function requireAuth(req: Request, res: Response, next: NextFunction): void {
  if (!AUTH_TOKEN) {
    const ip = req.ip ?? "";
    const isLoopback =
      ip === "127.0.0.1" || ip === "::1" || ip === "::ffff:127.0.0.1" || ip.startsWith("127.");
    if (!isLoopback) {
      res.status(401).json({
        error:
          "MCP_AUTH_TOKEN is not configured; non-loopback access is refused. Set MCP_AUTH_TOKEN to enable remote access.",
      });
      return;
    }
    next();
    return;
  }
  const header = req.header("authorization") ?? "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token || !constantTimeEqual(token, AUTH_TOKEN)) {
    res.status(401).json({ error: "unauthorized" });
    return;
  }
  next();
}

/**
 * Defense-in-depth against DNS rebinding and cross-origin attacks. Even if a
 * browser is tricked into pointing at 127.0.0.1, the `Host` header it sends
 * will be the attacker's domain — which won't match the allow-list and is
 * rejected here before any handler runs. CORS handles the same thing for
 * compliant browsers; this catches the rest.
 */
function validateOriginAndHost(req: Request, res: Response, next: NextFunction): void {
  const origin = req.header("origin");
  if (origin && ALLOWED_ORIGINS.length > 0 && !ALLOWED_ORIGINS.includes(origin)) {
    res.status(403).json({ error: "forbidden origin" });
    return;
  }
  const host = (req.header("host") ?? "").toLowerCase();
  const hostName = host.split(":")[0] ?? "";
  if (!ALLOWED_HOSTS.includes(hostName)) {
    res.status(403).json({ error: "forbidden host" });
    return;
  }
  next();
}

// ---------- Express app factory ----------

export interface BuildAppOptions {
  /** Optional pre-built KomodoClient — used by tests to inject a fake. */
  client?: KomodoClient;
}

export interface AppHandle {
  app: Express;
  closeAll: () => Promise<void>;
}

export function buildApp(options: BuildAppOptions = {}): AppHandle {
  const sharedClient = options.client ?? KomodoClient.fromEnv();

  const sessionIdleTimeoutRaw = env["MCP_SESSION_IDLE_TIMEOUT_MS"] ?? "1800000";
  const sessionIdleTimeoutMs = Number(sessionIdleTimeoutRaw);
  if (!Number.isInteger(sessionIdleTimeoutMs) || sessionIdleTimeoutMs < 1) {
    throw new Error(
      "Invalid MCP_SESSION_IDLE_TIMEOUT_MS: expected a positive integer (milliseconds)"
    );
  }

  const app = express();
  app.disable("x-powered-by");

  // Trust the loopback proxy only — req.ip then reflects X-Forwarded-For when
  // running behind a sidecar reverse proxy on the same host.
  app.set("trust proxy", "loopback");

  app.use(
    pinoHttp({
      logger,
      customLogLevel: (_req, res, err) => {
        if (err || res.statusCode >= 500) return "error";
        if (res.statusCode >= 400) return "warn";
        return "info";
      },
    })
  );
  // CSP is disabled because this server only emits JSON and SSE event streams
  // — there is no HTML surface for a CSP to protect. Helmet's other defaults
  // (X-Content-Type-Options, X-Frame-Options, Strict-Transport-Security on
  // HTTPS, etc.) still apply and are useful for any error pages Express might
  // render. If an HTML response path is ever added, re-enable CSP here with a
  // strict `default-src 'none'` policy.
  app.use(helmet({ contentSecurityPolicy: false }));
  app.use(
    cors({
      origin: ALLOWED_ORIGINS.length > 0 ? ALLOWED_ORIGINS : false,
      methods: ["GET", "POST", "DELETE", "OPTIONS"],
      credentials: false,
      exposedHeaders: ["mcp-session-id"],
    })
  );
  app.use(express.json({ limit: "2mb" }));

  app.get("/health", (_req: Request, res: Response) => {
    res.json({
      status: "ok",
      transport: TRANSPORT,
      port: PORT,
    });
  });

  // Per-session state. Each entry owns one McpServer and one transport.
  type StreamableSession = {
    transport: StreamableHTTPServerTransport;
    close: () => Promise<void>;
    touch: () => void;
  };
  type SseSession = {
    transport: SSEServerTransport;
    close: () => Promise<void>;
    touch: () => void;
  };
  const streamableSessions: Map<string, StreamableSession> = new Map();
  const sseSessions: Map<string, SseSession> = new Map();

  // Cap concurrent sessions to prevent an authenticated-but-misbehaving (or
  // unauthenticated-loopback) client from exhausting memory by opening
  // unbounded sessions. Override with MCP_MAX_SESSIONS.
  const maxSessionsRaw = env["MCP_MAX_SESSIONS"] ?? "100";
  const maxSessionsParsed = Number.parseInt(maxSessionsRaw, 10);
  const MAX_SESSIONS =
    Number.isInteger(maxSessionsParsed) && maxSessionsParsed > 0 ? maxSessionsParsed : 100;

  if (TRANSPORT === "streamable") {
    mountStreamable(app, streamableSessions, sharedClient, MAX_SESSIONS, sessionIdleTimeoutMs);
  } else if (TRANSPORT === "sse") {
    mountSse(app, sseSessions, sharedClient, MAX_SESSIONS, sessionIdleTimeoutMs);
  }

  // Final 4-arg error middleware — converts any uncaught handler error into a
  // 500 response without leaking internals.
  app.use((err: unknown, req: Request, res: Response, _next: NextFunction) => {
    logger.error({ err, path: req.path }, "unhandled error");
    if (!res.headersSent) {
      res.status(500).json({ error: "internal error" });
    }
  });

  const closeAll = async () => {
    const ops: Promise<unknown>[] = [];
    for (const session of streamableSessions.values()) {
      ops.push(session.close().catch(() => undefined));
    }
    for (const session of sseSessions.values()) {
      ops.push(session.close().catch(() => undefined));
    }
    streamableSessions.clear();
    sseSessions.clear();
    await Promise.all(ops);
    await sharedClient.close();
  };

  return { app, closeAll };
}

// ---------- Streamable HTTP wiring ----------

function mountStreamable(
  app: Express,
  sessions: Map<
    string,
    { transport: StreamableHTTPServerTransport; close: () => Promise<void>; touch: () => void }
  >,
  sharedClient: KomodoClient,
  maxSessions: number,
  sessionIdleTimeoutMs: number
): void {
  const handler = async (req: Request, res: Response) => {
    try {
      const sessionIdHeader = req.header("mcp-session-id") ?? undefined;
      if (sessionIdHeader) {
        const existing = sessions.get(sessionIdHeader);
        if (!existing) {
          res.status(404).json({ error: "Session not found" });
          return;
        }
        existing.touch();
        await existing.transport.handleRequest(req, res, req.body);
        return;
      }

      if (req.method !== "POST" || !isInitializeRequest(req.body)) {
        res.status(400).json({ error: "Initialization request required" });
        return;
      }

      if (sessions.size >= maxSessions) {
        logger.warn({ active: sessions.size, max: maxSessions }, "session cap reached");
        res.status(503).json({ error: "session capacity exhausted" });
        return;
      }

      // No existing session → create a new transport+server pair.
      const { server } = createServer({ client: sharedClient });
      // Re-entry guard: once we start tearing down, don't recurse through
      // server.close() ↔ transport.close() ↔ onclose.
      let closing = false;
      let idleTimer: NodeJS.Timeout | undefined;
      const cleanup = async () => {
        if (closing) return;
        closing = true;
        if (idleTimer) clearTimeout(idleTimer);
        const sid = transport.sessionId;
        if (sid) sessions.delete(sid);
        await server.close().catch(() => undefined);
      };
      const touch = () => {
        if (idleTimer) clearTimeout(idleTimer);
        idleTimer = setTimeout(() => {
          cleanup().catch(() => undefined);
        }, sessionIdleTimeoutMs);
        idleTimer.unref();
      };

      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (sid: string) => {
          sessions.set(sid, { transport, close: cleanup, touch });
          touch();
          logger.info({ sessionId: sid }, "streamable session opened");
        },
        onsessionclosed: async (sid: string) => {
          logger.info({ sessionId: sid }, "streamable session closed");
          await cleanup();
        },
      });

      transport.onclose = () => {
        cleanup().catch(() => undefined);
      };

      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (err) {
      logger.error({ err }, "streamable handler failure");
      if (!res.headersSent) {
        res.status(500).json({ error: "internal error" });
      }
    }
  };

  // Streamable HTTP only uses GET (open SSE upstream), POST (request), and
  // DELETE (close session). Restricting to those keeps stray verbs from
  // creating orphan sessions via the new-session path above.
  app.get("/mcp", validateOriginAndHost, requireAuth, handler);
  app.post("/mcp", validateOriginAndHost, requireAuth, handler);
  app.delete("/mcp", validateOriginAndHost, requireAuth, handler);
}

// ---------- legacy SSE wiring ----------

function mountSse(
  app: Express,
  sessions: Map<
    string,
    { transport: SSEServerTransport; close: () => Promise<void>; touch: () => void }
  >,
  sharedClient: KomodoClient,
  maxSessions: number,
  sessionIdleTimeoutMs: number
): void {
  app.get("/sse", validateOriginAndHost, requireAuth, async (_req: Request, res: Response) => {
    if (sessions.size >= maxSessions) {
      logger.warn({ active: sessions.size, max: maxSessions }, "sse session cap reached");
      res.status(503).json({ error: "session capacity exhausted" });
      return;
    }
    const { server } = createServer({ client: sharedClient });
    const transport = new SSEServerTransport("/messages", res);
    const sessionId = transport.sessionId;
    let closing = false;
    let idleTimer: NodeJS.Timeout | undefined;

    const cleanup = async () => {
      if (closing) return;
      closing = true;
      if (idleTimer) clearTimeout(idleTimer);
      sessions.delete(sessionId);
      await server.close().catch(() => undefined);
    };
    const touch = () => {
      if (idleTimer) clearTimeout(idleTimer);
      idleTimer = setTimeout(() => {
        cleanup().catch(() => undefined);
      }, sessionIdleTimeoutMs);
      idleTimer.unref();
    };

    transport.onclose = async () => {
      await cleanup();
      logger.info({ sessionId }, "sse session closed");
    };

    try {
      await server.connect(transport);
      sessions.set(sessionId, {
        transport,
        close: cleanup,
        touch,
      });
      touch();
      logger.info({ sessionId }, "sse session opened");
    } catch (err) {
      sessions.delete(sessionId);
      await server.close().catch(() => undefined);
      logger.error({ err }, "sse connect failed");
      if (!res.headersSent) {
        res.status(500).send("Error establishing SSE stream");
      }
    }
  });

  app.post("/messages", validateOriginAndHost, requireAuth, async (req: Request, res: Response) => {
    const sessionId = req.query["sessionId"] as string | undefined;
    if (!sessionId) {
      res.status(400).json({ error: "Missing sessionId parameter" });
      return;
    }
    const session = sessions.get(sessionId);
    if (!session) {
      res.status(404).json({ error: "Session not found" });
      return;
    }
    try {
      session.touch();
      await (session.transport as SSEServerTransport).handlePostMessage(req, res, req.body);
    } catch (err) {
      logger.error({ err }, "sse message handler failure");
      if (!res.headersSent) {
        res.status(500).json({ error: "Error handling request" });
      }
    }
  });
}

// ---------- main ----------

async function main(): Promise<void> {
  if (TRANSPORT === "stdio") {
    const { server } = createServer();
    logger.info("starting stdio transport");
    const transport = new StdioServerTransport();
    await server.connect(transport);
    logger.info("stdio transport ready");
    return;
  }

  const { app, closeAll } = buildApp();
  const httpServer: HttpServer = app.listen(PORT, BIND_HOST, () => {
    logger.info(
      {
        bindHost: BIND_HOST,
        port: PORT,
        transport: TRANSPORT,
        authConfigured: Boolean(AUTH_TOKEN),
      },
      "komodo-mcp listening"
    );
    if (!AUTH_TOKEN) {
      logger.warn("MCP_AUTH_TOKEN not set; only loopback (127.0.0.1) requests will be accepted");
    }
  });

  const shutdown = async (signal: NodeJS.Signals) => {
    logger.info({ signal }, "shutdown initiated");
    // Start the hard deadline before awaiting any potentially hung cleanup.
    const hardExit = setTimeout(() => {
      logger.warn("forced exit after 15s grace period");
      process.exit(1);
    }, 15_000);
    hardExit.unref();
    httpServer.close((err) => {
      if (err) logger.error({ err }, "httpServer.close error");
    });
    await closeAll();
  };

  process.on("SIGTERM", () => void shutdown("SIGTERM"));
  process.on("SIGINT", () => void shutdown("SIGINT"));
}

// Only run main when invoked as a binary, not when imported by tests.
const invokedDirectly =
  import.meta.url === `file://${process.argv[1]}` ||
  process.argv[1]?.endsWith("dist/index.js") === true;

if (invokedDirectly) {
  main().catch((error) => {
    // Log a sanitized representation — never the raw error object — so
    // environment-sourced secrets cannot reach stderr in clear text
    // (js/clear-text-logging). AUTH_TOKEN is the resolved MCP_AUTH_TOKEN
    // value (which may have come from MCP_AUTH_TOKEN_FILE).
    logger.error({ error: sanitizeErrorForLog(error, [AUTH_TOKEN]) }, "fatal error");
    process.exit(1);
  });
}
