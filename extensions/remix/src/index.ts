/**
 * ZASEON Remix IDE Plugin — Scan Solidity contracts for vulnerabilities
 * directly from the Remix editor.
 *
 * Features:
 * - One-click security scan of the active .sol file
 * - Inline severity annotations in the editor
 * - Expandable findings panel with remediation suggestions
 * - QuickScan via ZASEON API (cloud) or local engine
 */

import { PluginClient } from "@remixproject/plugin-webview";

// ── Plugin client ───────────────────────────────────────────────────────────

const client = new PluginClient();
const API_BASE = "https://api.zaseon.io"; // Configurable

interface ScanFinding {
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low" | "informational" | "gas";
  category: string;
  line_start: number;
  line_end: number;
  remediation?: string;
  cwe_id?: string;
}

interface ScanResponse {
  scan_id: string;
  security_score: number;
  findings: ScanFinding[];
}

// ── State ───────────────────────────────────────────────────────────────────

let currentFindings: ScanFinding[] = [];
let apiKey = "";
let endpoint = API_BASE;

// ── DOM helpers ─────────────────────────────────────────────────────────────

function $(id: string): HTMLElement {
  return document.getElementById(id)!;
}

function setScanState(
  state: "idle" | "scanning" | "done" | "error",
  message?: string,
) {
  const btn = $("scan-btn") as HTMLButtonElement;
  const status = $("status");

  switch (state) {
    case "idle":
      btn.disabled = false;
      btn.textContent = "🛡️ Scan Current File";
      status.textContent = "";
      break;
    case "scanning":
      btn.disabled = true;
      btn.textContent = "⏳ Scanning…";
      status.textContent = "Analyzing contract…";
      status.className = "text-blue";
      break;
    case "done":
      btn.disabled = false;
      btn.textContent = "🛡️ Scan Current File";
      status.textContent = message || "Done";
      status.className = "text-green";
      break;
    case "error":
      btn.disabled = false;
      btn.textContent = "🛡️ Scan Current File";
      status.textContent = `Error: ${message}`;
      status.className = "text-red";
      break;
  }
}

function severityColor(sev: string): string {
  const map: Record<string, string> = {
    critical: "#dc2626",
    high: "#ea580c",
    medium: "#ca8a04",
    low: "#2563eb",
    informational: "#6b7280",
    gas: "#8b5cf6",
  };
  return map[sev] || "#6b7280";
}

function renderFindings(findings: ScanFinding[], score: number) {
  const container = $("findings");
  currentFindings = findings;

  if (findings.length === 0) {
    container.innerHTML = `
      <div class="empty">
        <div style="font-size: 2rem">✅</div>
        <p>No vulnerabilities found!</p>
        <p class="score">Security Score: ${score}/100</p>
      </div>`;
    return;
  }

  // Group by severity
  const groups: Record<string, ScanFinding[]> = {};
  for (const f of findings) {
    (groups[f.severity] ??= []).push(f);
  }

  const sevOrder = [
    "critical",
    "high",
    "medium",
    "low",
    "informational",
    "gas",
  ];
  let html = `<div class="score-bar" style="--score: ${score}%">Score: ${score}/100</div>`;

  for (const sev of sevOrder) {
    const items = groups[sev];
    if (!items?.length) continue;

    html += `<div class="sev-group">
      <div class="sev-header" style="border-left: 3px solid ${severityColor(sev)}">
        <span class="sev-badge" style="background: ${severityColor(sev)}">${sev.toUpperCase()}</span>
        <span class="sev-count">${items.length}</span>
      </div>`;

    for (const f of items) {
      html += `
        <details class="finding">
          <summary>
            <span class="finding-title">${escapeHtml(f.title)}</span>
            <span class="finding-loc">L${f.line_start}</span>
          </summary>
          <div class="finding-body">
            <p>${escapeHtml(f.description)}</p>
            ${f.remediation ? `<div class="remediation"><strong>Fix:</strong> ${escapeHtml(f.remediation)}</div>` : ""}
            ${f.cwe_id ? `<span class="cwe">${f.cwe_id}</span>` : ""}
            <button class="goto-btn" data-line="${f.line_start}">Go to line ${f.line_start}</button>
          </div>
        </details>`;
    }
    html += `</div>`;
  }

  container.innerHTML = html;

  // Attach "Go to line" handlers
  container.querySelectorAll(".goto-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const line = parseInt((btn as HTMLElement).dataset.line || "1");
      highlightLine(line);
    });
  });
}

function escapeHtml(str: string): string {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// ── Remix editor integration ────────────────────────────────────────────────

async function highlightLine(line: number) {
  try {
    await client.call("editor" as any, "highlight", {
      position: {
        start: { line: line - 1, column: 0 },
        end: { line, column: 0 },
      },
      fileName: "",
    });
  } catch {
    // Fallback: just focus the editor
    await client.call("editor" as any, "focus");
  }
}

async function addAnnotations(findings: ScanFinding[], fileName: string) {
  try {
    const annotations = findings.map((f) => ({
      row: f.line_start - 1,
      column: 0,
      text: `[${f.severity.toUpperCase()}] ${f.title}`,
      type:
        f.severity === "critical" || f.severity === "high"
          ? "error"
          : "warning",
    }));

    await client.call("editor" as any, "addAnnotation", {
      key: "zaseon",
      value: annotations,
    });
  } catch (e) {
    console.warn("Could not add annotations:", e);
  }
}

// ── API call ────────────────────────────────────────────────────────────────

async function scanCurrentFile() {
  setScanState("scanning");

  try {
    // Get current file from Remix
    const fileName = await client.call("fileManager" as any, "getCurrentFile");
    if (!fileName || !fileName.endsWith(".sol")) {
      setScanState("error", "Open a .sol file first");
      return;
    }

    const sourceCode = await client.call(
      "fileManager" as any,
      "readFile",
      fileName,
    );
    if (!sourceCode?.trim()) {
      setScanState("error", "File is empty");
      return;
    }

    // Call ZASEON quickscan API
    const response = await fetch(`${endpoint}/api/v1/quickscan/source`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(apiKey ? { Authorization: `Bearer ${apiKey}` } : {}),
      },
      body: JSON.stringify({ source_code: sourceCode, file_name: fileName }),
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.detail || `HTTP ${response.status}`);
    }

    const data: ScanResponse = await response.json();

    // Render results
    renderFindings(data.findings, data.security_score);
    await addAnnotations(data.findings, fileName);

    const msg =
      data.findings.length === 0
        ? "No issues found ✓"
        : `${data.findings.length} finding(s) — Score: ${data.security_score}/100`;
    setScanState("done", msg);
  } catch (err: any) {
    setScanState("error", err.message || "Scan failed");
  }
}

// ── Settings ────────────────────────────────────────────────────────────────

function loadSettings() {
  try {
    apiKey = localStorage.getItem("zaseon_api_key") || "";
    endpoint = localStorage.getItem("zaseon_endpoint") || API_BASE;
    ($("api-key") as HTMLInputElement).value = apiKey;
    ($("api-endpoint") as HTMLInputElement).value = endpoint;
  } catch {}
}

function saveSettings() {
  apiKey = ($("api-key") as HTMLInputElement).value.trim();
  endpoint = ($("api-endpoint") as HTMLInputElement).value.trim() || API_BASE;
  localStorage.setItem("zaseon_api_key", apiKey);
  localStorage.setItem("zaseon_endpoint", endpoint);
  $("settings-status").textContent = "Saved ✓";
  setTimeout(() => ($("settings-status").textContent = ""), 2000);
}

// ── Init ────────────────────────────────────────────────────────────────────

client.onload(async () => {
  loadSettings();

  $("scan-btn").addEventListener("click", scanCurrentFile);
  $("save-settings").addEventListener("click", saveSettings);

  // Tab switching
  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const tab = (btn as HTMLElement).dataset.tab!;
      document
        .querySelectorAll(".tab-btn")
        .forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      document
        .querySelectorAll(".tab-panel")
        .forEach((p) => p.classList.add("hidden"));
      $(tab).classList.remove("hidden");
    });
  });
});
