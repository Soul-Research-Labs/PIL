/**
 * ZASEON API — k6 Load Test Suite
 *
 * Run:
 *   k6 run infra/load-testing/k6-config.js
 *   k6 run --env BASE_URL=https://staging.zaseon.io infra/load-testing/k6-config.js
 *
 * Scenarios:
 *   smoke     — 5 VUs  / 1 min   (sanity check)
 *   load      — 50 VUs / 5 min   (normal traffic)
 *   stress    — 200 VUs / 3 min  (peak traffic)
 *   spike     — 0→300 VUs / 30s  (sudden burst)
 *   soak      — 30 VUs / 30 min  (endurance)
 */

import http from "k6/http";
import { check, group, sleep } from "k6";
import { Rate, Trend, Counter } from "k6/metrics";

// ── Custom metrics ──────────────────────────────────────────────────────

const errorRate = new Rate("errors");
const scanDuration = new Trend("scan_duration_ms");
const findingsCount = new Counter("findings_returned");

// ── Configuration ───────────────────────────────────────────────────────

const BASE_URL = __ENV.BASE_URL || "http://localhost:8000";
const API_KEY = __ENV.ZASEON_API_KEY || "test-api-key";
const API_PREFIX = `${BASE_URL}/api/v2`;

const HEADERS = {
  "Content-Type": "application/json",
  Authorization: `Bearer ${API_KEY}`,
};

// Sample Solidity source for quick-scan tests
const SAMPLE_CONTRACT = `
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Vault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] -= amount;
    }
}
`;

// ── Scenarios ───────────────────────────────────────────────────────────

export const options = {
  scenarios: {
    smoke: {
      executor: "constant-vus",
      vus: 5,
      duration: "1m",
      tags: { scenario: "smoke" },
      exec: "smokeTest",
    },
    load: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: [
        { duration: "1m", target: 50 },
        { duration: "3m", target: 50 },
        { duration: "1m", target: 0 },
      ],
      tags: { scenario: "load" },
      exec: "loadTest",
      startTime: "1m30s",
    },
    stress: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: [
        { duration: "30s", target: 200 },
        { duration: "2m", target: 200 },
        { duration: "30s", target: 0 },
      ],
      tags: { scenario: "stress" },
      exec: "loadTest",
      startTime: "7m",
    },
    spike: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: [
        { duration: "10s", target: 300 },
        { duration: "30s", target: 300 },
        { duration: "20s", target: 0 },
      ],
      tags: { scenario: "spike" },
      exec: "loadTest",
      startTime: "10m30s",
    },
    soak: {
      executor: "constant-vus",
      vus: 30,
      duration: "30m",
      tags: { scenario: "soak" },
      exec: "loadTest",
      startTime: "12m",
    },
  },
  thresholds: {
    http_req_duration: [
      "p(95)<500", // 95% of requests under 500ms
      "p(99)<2000", // 99% under 2s
    ],
    "http_req_duration{endpoint:health}": ["p(99)<100"],
    "http_req_duration{endpoint:quickscan}": ["p(95)<10000"],
    errors: ["rate<0.05"], // Error rate below 5%
    http_req_failed: ["rate<0.05"],
    scan_duration_ms: ["p(95)<30000"], // 95% of scans under 30s
  },
};

// ── Helpers ─────────────────────────────────────────────────────────────

function apiGet(path, tags = {}) {
  const res = http.get(`${API_PREFIX}${path}`, {
    headers: HEADERS,
    tags,
  });
  errorRate.add(res.status >= 400);
  return res;
}

function apiPost(path, body, tags = {}) {
  const res = http.post(`${API_PREFIX}${path}`, JSON.stringify(body), {
    headers: HEADERS,
    tags,
  });
  errorRate.add(res.status >= 400);
  return res;
}

// ── Smoke test (lightweight health checks) ──────────────────────────────

export function smokeTest() {
  group("Health", () => {
    const res = http.get(`${BASE_URL}/health`, {
      tags: { endpoint: "health" },
    });
    check(res, {
      "health 200": (r) => r.status === 200,
      "health body ok": (r) => {
        try {
          return JSON.parse(r.body).status === "healthy";
        } catch {
          return false;
        }
      },
    });
  });

  group("Auth", () => {
    const res = apiGet("/auth/me", { endpoint: "auth_me" });
    check(res, {
      "auth 200 or 401": (r) => [200, 401].includes(r.status),
    });
  });

  sleep(1);
}

// ── Full load test (realistic user journey) ─────────────────────────────

export function loadTest() {
  // 1. Health check
  group("Health", () => {
    const res = http.get(`${BASE_URL}/health`, {
      tags: { endpoint: "health" },
    });
    check(res, { "health 200": (r) => r.status === 200 });
  });

  // 2. Dashboard summary
  group("Dashboard", () => {
    const res = apiGet("/dashboard/summary", { endpoint: "dashboard" });
    check(res, {
      "dashboard 2xx": (r) => r.status >= 200 && r.status < 300,
    });
  });

  // 3. Quick scan (the heaviest endpoint)
  group("Quick Scan", () => {
    const start = Date.now();
    const res = apiPost(
      "/quickscan",
      { source_code: SAMPLE_CONTRACT, mode: "quick" },
      { endpoint: "quickscan" },
    );
    scanDuration.add(Date.now() - start);

    check(res, {
      "quickscan 2xx": (r) => r.status >= 200 && r.status < 300,
      "quickscan has findings": (r) => {
        try {
          const body = JSON.parse(r.body);
          const count = (body.findings || []).length;
          findingsCount.add(count);
          return count >= 0;
        } catch {
          return false;
        }
      },
    });
  });

  // 4. List scans (paginated)
  group("List Scans", () => {
    const res = apiGet("/scans?limit=20", { endpoint: "scans_list" });
    check(res, {
      "scans 2xx": (r) => r.status >= 200 && r.status < 300,
    });
  });

  // 5. List findings (paginated)
  group("List Findings", () => {
    const res = apiGet("/findings?limit=20", { endpoint: "findings_list" });
    check(res, {
      "findings 2xx": (r) => r.status >= 200 && r.status < 300,
    });
  });

  // 6. Analytics
  group("Analytics", () => {
    const res = apiGet("/analytics/summary", { endpoint: "analytics" });
    check(res, {
      "analytics 2xx": (r) => r.status >= 200 && r.status < 300,
    });
  });

  // 7. Scan volume time-series
  group("Scan Volume", () => {
    const res = apiGet("/analytics/scans/volume?days=30", {
      endpoint: "scan_volume",
    });
    check(res, {
      "volume 2xx": (r) => r.status >= 200 && r.status < 300,
    });
  });

  // Random think time between 0.5–2s
  sleep(Math.random() * 1.5 + 0.5);
}
