/**
 * TreeDataProvider for the ZASEON Findings sidebar panel.
 */

import * as vscode from "vscode";

interface Finding {
  title: string;
  severity: string;
  description: string;
  start_line: number;
  end_line: number;
  category?: string;
  remediation?: string;
}

export class FindingsProvider implements vscode.TreeDataProvider<FindingItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<
    FindingItem | undefined | null | void
  >();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private findings: Finding[] = [];

  update(findings: Finding[]) {
    this.findings = findings;
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element: FindingItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: FindingItem): Thenable<FindingItem[]> {
    if (element) {
      // Children of a finding: details
      return Promise.resolve([
        new FindingItem(
          `Description: ${element.finding.description}`,
          vscode.TreeItemCollapsibleState.None,
        ),
        new FindingItem(
          `Lines: ${element.finding.start_line}-${element.finding.end_line}`,
          vscode.TreeItemCollapsibleState.None,
        ),
        ...(element.finding.remediation
          ? [
              new FindingItem(
                `Fix: ${element.finding.remediation}`,
                vscode.TreeItemCollapsibleState.None,
              ),
            ]
          : []),
      ]);
    }

    // Root: group by severity
    const grouped = new Map<string, Finding[]>();
    for (const f of this.findings) {
      const sev = f.severity;
      if (!grouped.has(sev)) grouped.set(sev, []);
      grouped.get(sev)!.push(f);
    }

    const items: FindingItem[] = [];
    for (const [severity, findings] of grouped) {
      for (const f of findings) {
        const icon = severityIcon(severity);
        const item = new FindingItem(
          `${icon} [${severity.toUpperCase()}] ${f.title}`,
          vscode.TreeItemCollapsibleState.Collapsed,
          f,
        );
        items.push(item);
      }
    }

    return Promise.resolve(items);
  }
}

class FindingItem extends vscode.TreeItem {
  constructor(
    public readonly label: string,
    public readonly collapsibleState: vscode.TreeItemCollapsibleState,
    public readonly finding: Finding = {
      title: "",
      severity: "",
      description: label,
      start_line: 0,
      end_line: 0,
    },
  ) {
    super(label, collapsibleState);
    this.tooltip = finding.description || label;
  }
}

function severityIcon(severity: string): string {
  switch (severity.toLowerCase()) {
    case "critical":
      return "🔴";
    case "high":
      return "🟠";
    case "medium":
      return "🟡";
    case "low":
      return "🔵";
    case "informational":
      return "⚪";
    default:
      return "⚫";
  }
}
