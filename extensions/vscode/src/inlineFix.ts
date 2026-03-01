/**
 * ZASEON Inline Fix Provider — CodeAction + quick-fix integration.
 *
 * Provides:
 * - CodeActionProvider that offers LLM-powered fix suggestions for ZASEON diagnostics
 * - Inline diff preview before applying patches
 * - One-click "Apply Fix" and "Explain Finding" actions
 */

import * as vscode from "vscode";
import { ZaseonClient } from "./client";

/** A remediation suggestion returned by the API. */
interface RemediationSuggestion {
  title: string;
  description: string;
  patch_diff: string;
  confidence: number;
  gas_saved?: number;
}

/**
 * CodeAction provider that attaches quick-fix actions to ZASEON diagnostics.
 *
 * When the user clicks the lightbulb or presses Cmd+. on a ZASEON diagnostic,
 * this provider offers:
 * 1. "Apply ZASEON Fix" — applies the LLM-generated patch inline
 * 2. "Explain Finding" — shows a detailed explanation in a webview panel
 */
export class ZaseonCodeActionProvider implements vscode.CodeActionProvider {
  public static readonly providedCodeActionKinds = [
    vscode.CodeActionKind.QuickFix,
  ];

  private client: ZaseonClient;
  private cache = new Map<string, RemediationSuggestion[]>();

  constructor(client: ZaseonClient) {
    this.client = client;
  }

  async provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range,
    context: vscode.CodeActionContext,
    _token: vscode.CancellationToken,
  ): Promise<vscode.CodeAction[]> {
    const actions: vscode.CodeAction[] = [];

    for (const diag of context.diagnostics) {
      if (diag.source !== "ZASEON") continue;

      // "Apply Fix" action
      const fixAction = new vscode.CodeAction(
        `ZASEON: Apply Fix`,
        vscode.CodeActionKind.QuickFix,
      );
      fixAction.diagnostics = [diag];
      fixAction.isPreferred = true;
      fixAction.command = {
        command: "zaseon.applyInlineFix",
        title: "Apply ZASEON Fix",
        arguments: [document.uri, diag],
      };
      actions.push(fixAction);

      // "Explain" action
      const explainAction = new vscode.CodeAction(
        `ZASEON: Explain Finding`,
        vscode.CodeActionKind.QuickFix,
      );
      explainAction.diagnostics = [diag];
      explainAction.command = {
        command: "zaseon.explainFinding",
        title: "Explain Finding",
        arguments: [document.uri, diag],
      };
      actions.push(explainAction);
    }

    return actions;
  }
}

/**
 * Register the inline fix commands and CodeAction provider.
 */
export function registerInlineFixProvider(
  context: vscode.ExtensionContext,
  client: ZaseonClient,
) {
  const provider = new ZaseonCodeActionProvider(client);

  // Register for Solidity and Vyper files
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      [
        { language: "solidity", scheme: "file" },
        { language: "vyper", scheme: "file" },
        { pattern: "**/*.sol" },
        { pattern: "**/*.vy" },
      ],
      provider,
      {
        providedCodeActionKinds:
          ZaseonCodeActionProvider.providedCodeActionKinds,
      },
    ),
  );

  // ── Apply Fix command ─────────────────────────────────────────────────
  context.subscriptions.push(
    vscode.commands.registerCommand(
      "zaseon.applyInlineFix",
      async (uri: vscode.Uri, diag: vscode.Diagnostic) => {
        const document = await vscode.workspace.openTextDocument(uri);
        const source = document.getText();
        const findingTitle = extractFindingTitle(diag.message);

        await vscode.window.withProgress(
          {
            location: vscode.ProgressLocation.Notification,
            title: "ZASEON: Generating fix...",
            cancellable: false,
          },
          async () => {
            try {
              const suggestions = await client.getRemediation(
                source,
                document.fileName,
                findingTitle,
                diag.range.start.line + 1,
                diag.range.end.line + 1,
              );

              if (!suggestions || suggestions.length === 0) {
                vscode.window.showWarningMessage(
                  "ZASEON: No fix suggestions available.",
                );
                return;
              }

              // If multiple suggestions, let user pick
              const selected =
                suggestions.length === 1
                  ? suggestions[0]
                  : await pickSuggestion(suggestions);

              if (!selected) return;

              // Apply the patch as a workspace edit
              const applied = await applyPatchDiff(uri, selected.patch_diff);
              if (applied) {
                vscode.window.showInformationMessage(
                  `ZASEON: Fix applied — ${selected.title}` +
                    (selected.gas_saved
                      ? ` (saves ~${selected.gas_saved} gas)`
                      : ""),
                );
              }
            } catch (err: any) {
              vscode.window.showErrorMessage(
                `ZASEON fix failed: ${err.message}`,
              );
            }
          },
        );
      },
    ),
  );

  // ── Explain Finding command ───────────────────────────────────────────
  context.subscriptions.push(
    vscode.commands.registerCommand(
      "zaseon.explainFinding",
      async (uri: vscode.Uri, diag: vscode.Diagnostic) => {
        const document = await vscode.workspace.openTextDocument(uri);
        const source = document.getText();
        const snippet = document.getText(diag.range);
        const findingTitle = extractFindingTitle(diag.message);

        await vscode.window.withProgress(
          {
            location: vscode.ProgressLocation.Notification,
            title: "ZASEON: Generating explanation...",
            cancellable: false,
          },
          async () => {
            try {
              const explanation = await client.explainFinding(
                source,
                snippet,
                findingTitle,
              );

              // Show in a webview panel
              const panel = vscode.window.createWebviewPanel(
                "zaseonExplain",
                `ZASEON: ${findingTitle}`,
                vscode.ViewColumn.Beside,
                { enableScripts: false },
              );

              panel.webview.html = renderExplanationHtml(
                findingTitle,
                explanation,
                diag,
              );
            } catch (err: any) {
              vscode.window.showErrorMessage(
                `ZASEON explain failed: ${err.message}`,
              );
            }
          },
        );
      },
    ),
  );
}

// ── Helpers ─────────────────────────────────────────────────────────────────

function extractFindingTitle(diagMessage: string): string {
  // Diagnostic messages are formatted as "[ZASEON] Title: Description"
  const match = diagMessage.match(/\[ZASEON\]\s*(.+?):\s*/);
  return match ? match[1].trim() : diagMessage;
}

async function pickSuggestion(
  suggestions: RemediationSuggestion[],
): Promise<RemediationSuggestion | undefined> {
  const items = suggestions.map((s, i) => ({
    label: s.title,
    description: `${(s.confidence * 100).toFixed(0)}% confidence${s.gas_saved ? ` • saves ${s.gas_saved} gas` : ""}`,
    detail: s.description,
    index: i,
  }));

  const picked = await vscode.window.showQuickPick(items, {
    placeHolder: "Select a fix to apply",
  });

  return picked ? suggestions[picked.index] : undefined;
}

async function applyPatchDiff(
  uri: vscode.Uri,
  patchDiff: string,
): Promise<boolean> {
  /**
   * Parse a unified diff and apply it as a workspace edit.
   * Supports simple single-hunk patches (most LLM-generated patches).
   */
  const edit = new vscode.WorkspaceEdit();
  const lines = patchDiff.split("\n");

  let startLine = 0;
  let deleteCount = 0;
  const insertLines: string[] = [];
  let inHunk = false;

  for (const line of lines) {
    // Parse hunk header: @@ -start,count +start,count @@
    const hunkMatch = line.match(/^@@\s*-(\d+),?\d*\s*\+\d+,?\d*\s*@@/);
    if (hunkMatch) {
      startLine = parseInt(hunkMatch[1], 10) - 1; // 0-indexed
      inHunk = true;
      continue;
    }

    if (!inHunk) continue;

    if (line.startsWith("-") && !line.startsWith("---")) {
      deleteCount++;
    } else if (line.startsWith("+") && !line.startsWith("+++")) {
      insertLines.push(line.substring(1));
    } else if (line.startsWith(" ")) {
      // Context line — count in both
      deleteCount++;
      insertLines.push(line.substring(1));
    }
  }

  if (deleteCount === 0 && insertLines.length === 0) {
    vscode.window.showWarningMessage("ZASEON: Could not parse patch diff.");
    return false;
  }

  const range = new vscode.Range(startLine, 0, startLine + deleteCount, 0);
  edit.replace(
    uri,
    range,
    insertLines.join("\n") + (insertLines.length > 0 ? "\n" : ""),
  );
  return vscode.workspace.applyEdit(edit);
}

function renderExplanationHtml(
  title: string,
  explanation: {
    summary: string;
    impact: string;
    attack_scenario: string;
    recommendation: string;
    references: string[];
  },
  diag: vscode.Diagnostic,
): string {
  const sevColor: Record<string, string> = {
    [vscode.DiagnosticSeverity.Error]: "#e53e3e",
    [vscode.DiagnosticSeverity.Warning]: "#dd6b20",
    [vscode.DiagnosticSeverity.Information]: "#3182ce",
    [vscode.DiagnosticSeverity.Hint]: "#718096",
  };
  const color = sevColor[diag.severity] || "#718096";

  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; padding: 20px; color: var(--vscode-foreground); background: var(--vscode-editor-background); }
    h1 { font-size: 18px; border-left: 4px solid ${color}; padding-left: 12px; }
    h2 { font-size: 14px; color: var(--vscode-descriptionForeground); margin-top: 20px; }
    p { line-height: 1.6; }
    pre { background: var(--vscode-textCodeBlock-background); padding: 12px; border-radius: 4px; overflow-x: auto; }
    .refs { font-size: 12px; color: var(--vscode-textLink-foreground); }
    .refs a { color: var(--vscode-textLink-foreground); }
  </style>
</head>
<body>
  <h1>${escapeHtml(title)}</h1>
  <p>Lines ${diag.range.start.line + 1}–${diag.range.end.line + 1}</p>

  <h2>Summary</h2>
  <p>${escapeHtml(explanation.summary)}</p>

  <h2>Impact</h2>
  <p>${escapeHtml(explanation.impact)}</p>

  <h2>Attack Scenario</h2>
  <pre>${escapeHtml(explanation.attack_scenario)}</pre>

  <h2>Recommendation</h2>
  <p>${escapeHtml(explanation.recommendation)}</p>

  ${
    explanation.references.length > 0
      ? `<h2>References</h2><div class="refs">${explanation.references.map((r) => `<div>• ${escapeHtml(r)}</div>`).join("")}</div>`
      : ""
  }
</body>
</html>`;
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
