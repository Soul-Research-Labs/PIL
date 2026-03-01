/**
 * ZASEON VS Code Extension — Main Entry Point
 *
 * Provides inline diagnostics, commands, and sidebar panels
 * for Solidity smart contract security scanning.
 */

import * as vscode from "vscode";
import { ZaseonClient } from "./client";
import { FindingsProvider } from "./findingsProvider";
import { registerInlineFixProvider } from "./inlineFix";

let client: ZaseonClient;
let diagnosticCollection: vscode.DiagnosticCollection;
let findingsProvider: FindingsProvider;

export function activate(context: vscode.ExtensionContext) {
  console.log("ZASEON extension activated");

  // Initialize client
  const config = vscode.workspace.getConfiguration("zaseon");
  const apiUrl = config.get<string>("apiUrl", "http://localhost:8000");
  const apiKey = config.get<string>("apiKey", "");
  client = new ZaseonClient(apiUrl, apiKey);

  // Diagnostics collection
  diagnosticCollection = vscode.languages.createDiagnosticCollection("zaseon");
  context.subscriptions.push(diagnosticCollection);

  // Findings tree view
  findingsProvider = new FindingsProvider();
  vscode.window.registerTreeDataProvider("zaseon.findings", findingsProvider);

  // ── Commands ──────────────────────────────────────────────────────────

  // Scan current file
  context.subscriptions.push(
    vscode.commands.registerCommand("zaseon.scanFile", async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor || !editor.document.fileName.endsWith(".sol")) {
        vscode.window.showWarningMessage("ZASEON: Open a .sol file to scan.");
        return;
      }

      const source = editor.document.getText();
      const fileName = editor.document.fileName;

      await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: "ZASEON: Scanning...",
          cancellable: false,
        },
        async () => {
          try {
            const result = await client.quickScan(source, fileName);
            updateDiagnostics(editor.document.uri, result.findings || []);
            findingsProvider.update(result.findings || []);

            const count = result.findings?.length || 0;
            vscode.window.showInformationMessage(
              `ZASEON: Found ${count} issue${count !== 1 ? "s" : ""} (Score: ${result.security_score ?? "N/A"}).`,
            );
          } catch (err: any) {
            vscode.window.showErrorMessage(
              `ZASEON scan failed: ${err.message}`,
            );
          }
        },
      );
    }),
  );

  // Scan workspace
  context.subscriptions.push(
    vscode.commands.registerCommand("zaseon.scanWorkspace", async () => {
      const files = await vscode.workspace.findFiles(
        "**/*.sol",
        "**/node_modules/**",
      );
      if (files.length === 0) {
        vscode.window.showWarningMessage(
          "ZASEON: No .sol files found in workspace.",
        );
        return;
      }

      vscode.window.showInformationMessage(
        `ZASEON: Scanning ${files.length} Solidity file${files.length !== 1 ? "s" : ""}...`,
      );

      // Batch scan implementation would go here
      vscode.window.showInformationMessage("ZASEON: Workspace scan queued.");
    }),
  );

  // Start fuzzer campaign
  context.subscriptions.push(
    vscode.commands.registerCommand("zaseon.startFuzzer", async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor || !editor.document.fileName.endsWith(".sol")) {
        vscode.window.showWarningMessage("ZASEON: Open a .sol file to fuzz.");
        return;
      }

      const mode = await vscode.window.showQuickPick(
        ["quick", "standard", "deep", "exhaustive"],
        { placeHolder: "Select fuzzer mode" },
      );
      if (!mode) return;

      const source = editor.document.getText();

      try {
        const result = await client.startCampaign(source, mode);
        vscode.window.showInformationMessage(
          `ZASEON: Fuzzer campaign started (ID: ${result.campaign_id}).`,
        );
      } catch (err: any) {
        vscode.window.showErrorMessage(`ZASEON fuzzer failed: ${err.message}`);
      }
    }),
  );

  // Show findings panel
  context.subscriptions.push(
    vscode.commands.registerCommand("zaseon.showFindings", () => {
      vscode.commands.executeCommand("zaseon.findings.focus");
    }),
  );

  // Auto-scan on save
  if (config.get<boolean>("autoScanOnSave")) {
    context.subscriptions.push(
      vscode.workspace.onDidSaveTextDocument(async (doc) => {
        if (doc.fileName.endsWith(".sol")) {
          vscode.commands.executeCommand("zaseon.scanFile");
        }
      }),
    );
  }

  // ── Inline Fix Provider (CodeAction + quick-fix) ──────────────────────
  registerInlineFixProvider(context, client);
}

export function deactivate() {
  diagnosticCollection?.dispose();
}

// ── Helpers ─────────────────────────────────────────────────────────────────

function updateDiagnostics(
  uri: vscode.Uri,
  findings: Array<{
    title: string;
    severity: string;
    description: string;
    start_line: number;
    end_line: number;
  }>,
) {
  const config = vscode.workspace.getConfiguration("zaseon");
  if (!config.get<boolean>("showInlineDiagnostics", true)) return;

  const severityFilter = config.get<string>("severityFilter", "all");
  const severityMap: Record<string, vscode.DiagnosticSeverity> = {
    critical: vscode.DiagnosticSeverity.Error,
    high: vscode.DiagnosticSeverity.Error,
    medium: vscode.DiagnosticSeverity.Warning,
    low: vscode.DiagnosticSeverity.Information,
    informational: vscode.DiagnosticSeverity.Hint,
    gas: vscode.DiagnosticSeverity.Hint,
  };

  const filterOrder = ["all", "critical", "high", "medium"];
  const filterIndex = filterOrder.indexOf(severityFilter);

  const diagnostics = findings
    .filter((f) => {
      if (severityFilter === "all") return true;
      const sevOrder = [
        "critical",
        "high",
        "medium",
        "low",
        "informational",
        "gas",
      ];
      return sevOrder.indexOf(f.severity) <= filterIndex - 1;
    })
    .map((f) => {
      const range = new vscode.Range(
        Math.max(0, f.start_line - 1),
        0,
        Math.max(0, f.end_line - 1),
        Number.MAX_VALUE,
      );
      const diag = new vscode.Diagnostic(
        range,
        `[ZASEON] ${f.title}: ${f.description}`,
        severityMap[f.severity] || vscode.DiagnosticSeverity.Warning,
      );
      diag.source = "ZASEON";
      return diag;
    });

  diagnosticCollection.set(uri, diagnostics);
}
