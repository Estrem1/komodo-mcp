// Regression test for GitHub code-scanning alert #18 (js/clear-text-logging):
// the fatal-error sink must log a sanitized error representation (name,
// message, stack) with environment-sourced secrets redacted — never the raw
// thrown object. Spawns the real CLI (dist/index.js) with poisoned env so the
// actual fatal log output on stderr is what gets asserted.

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const REPO_ROOT = fileURLToPath(new URL("..", import.meta.url));

const SECRET_KEY = "SecretApiKey-4f8a2c7b";
const SECRET_SECRET = "SecretApiSecret-9d21be03";
const SECRET_TOKEN = "SecretAuthToken-5c4d2f61";
const SECRET_URL = "SecretAddressValue-7f3a9c15";
const SECRET_NUMBER = "SecretTimeoutValue-2e8b40da";
const SECRET_PATH = "/nonexistent/SecretPathValue-b1d73f92/creds";

/** Spawn dist/index.js with poisoned env and collect its stderr until exit. */
function runFatal(extraEnv) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["dist/index.js"], {
      cwd: REPO_ROOT,
      env: { ...process.env, ...extraEnv },
      stdio: ["ignore", "ignore", "pipe"],
    });
    let stderr = "";
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("child process did not exit within 20s"));
    }, 20_000);
    child.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stderr });
    });
  });
}

function parseFatalLine(stderr) {
  for (const line of stderr.split("\n")) {
    try {
      const parsed = JSON.parse(line);
      if (parsed.msg === "fatal error") return parsed;
    } catch {
      // not a JSON line — skip
    }
  }
  return undefined;
}

function assertNoSecrets(stderr, label) {
  for (const secret of [
    SECRET_KEY,
    SECRET_SECRET,
    SECRET_TOKEN,
    SECRET_URL,
    SECRET_NUMBER,
    SECRET_PATH,
  ]) {
    assert.ok(!stderr.includes(secret), `${label}: fatal log must not contain ${secret}`);
  }
}

test("fatal error log is sanitized: no env values or secrets, actionable message", async () => {
  // Each scenario crashes main() through a different config-error path; all
  // three secret-bearing env vars are set in every run.
  const scenarios = [
    {
      name: "invalid KOMODO_ADDRESS URL",
      env: {
        KOMODO_ADDRESS: `http://not a valid url -- ${SECRET_URL}`,
        KOMODO_API_KEY: SECRET_KEY,
        KOMODO_API_SECRET: SECRET_SECRET,
        MCP_AUTH_TOKEN: SECRET_TOKEN,
      },
      messageRe: /KOMODO_ADDRESS is not a valid URL/,
    },
    {
      name: "non-http KOMODO_ADDRESS scheme",
      env: {
        KOMODO_ADDRESS: `ftp://${SECRET_URL}/x`,
        KOMODO_API_KEY: SECRET_KEY,
        KOMODO_API_SECRET: SECRET_SECRET,
        MCP_AUTH_TOKEN: SECRET_TOKEN,
      },
      messageRe: /KOMODO_ADDRESS must be http/,
    },
    {
      name: "invalid KOMODO_TIMEOUT_MS",
      env: {
        KOMODO_ADDRESS: "http://127.0.0.1:1",
        KOMODO_API_KEY: SECRET_KEY,
        KOMODO_API_SECRET: SECRET_SECRET,
        MCP_AUTH_TOKEN: SECRET_TOKEN,
        KOMODO_TIMEOUT_MS: SECRET_NUMBER,
      },
      messageRe: /Invalid KOMODO_TIMEOUT_MS: expected a positive integer/,
    },
    {
      name: "unreadable KOMODO_ADDRESS_FILE",
      env: {
        KOMODO_ADDRESS_FILE: SECRET_PATH,
        KOMODO_API_KEY: SECRET_KEY,
        KOMODO_API_SECRET: SECRET_SECRET,
        MCP_AUTH_TOKEN: SECRET_TOKEN,
      },
      messageRe: /Failed to read KOMODO_ADDRESS_FILE/,
    },
  ];

  for (const scenario of scenarios) {
    const { code, stderr } = await runFatal(scenario.env);
    assert.equal(code, 1, `${scenario.name}: expected exit code 1`);
    const fatal = parseFatalLine(stderr);
    assert.ok(fatal, `${scenario.name}: no "fatal error" log line found. stderr: ${stderr}`);
    assert.equal(
      fatal.error?.name,
      "Error",
      `${scenario.name}: sanitized error must keep name. stderr: ${stderr}`
    );
    assert.match(
      String(fatal.error?.message),
      scenario.messageRe,
      `${scenario.name}: sanitized message must name the variable and expected shape, value-free. stderr: ${stderr}`
    );
    assert.equal(
      typeof fatal.error?.stack,
      "string",
      `${scenario.name}: stack must be kept for debugging`
    );
    assertNoSecrets(stderr, scenario.name);
  }
});

test("sanitizeErrorForLog redacts secrets and drops non-core fields", async () => {
  const { sanitizeErrorForLog } = await import("../dist/komodo-client.js");
  const original = { ...process.env };
  try {
    // Secrets known via process.env (the helper's own redaction source)…
    process.env.KOMODO_API_KEY = SECRET_KEY;
    process.env.KOMODO_API_SECRET = SECRET_SECRET;
    process.env.MCP_AUTH_TOKEN = SECRET_TOKEN;
    const error = new Error(`boom key=${SECRET_KEY} token=${SECRET_TOKEN} num=${SECRET_NUMBER}`, {
      cause: new Error(`inner ${SECRET_SECRET}`),
    });
    error.extra = SECRET_URL; // enumerable custom property must not survive
    // …plus a value passed explicitly (e.g. one resolved from a *_FILE var).
    const sanitized = sanitizeErrorForLog(error, [SECRET_NUMBER]);
    const json = JSON.stringify(sanitized);
    assert.match(json, /boom key=\[redacted\] token=\[redacted\] num=\[redacted\]/);
    for (const secret of [SECRET_KEY, SECRET_SECRET, SECRET_TOKEN, SECRET_NUMBER, SECRET_URL]) {
      assert.ok(!json.includes(secret), `sanitized log must not contain ${secret}`);
    }
    assert.ok(!json.includes("inner"), "cause chain must be dropped");
    assert.ok(!("cause" in sanitized), "cause chain must be dropped");
    assert.ok(!("extra" in sanitized), "custom properties must be dropped");
  } finally {
    for (const key of ["KOMODO_API_KEY", "KOMODO_API_SECRET", "MCP_AUTH_TOKEN"]) {
      if (!(key in original)) delete process.env[key];
      else process.env[key] = original[key];
    }
  }
});
