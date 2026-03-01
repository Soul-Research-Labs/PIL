/**
 * ZASEON API client for the VS Code extension.
 */

import axios, { AxiosInstance } from "axios";

export interface QuickScanResult {
  findings: Array<{
    title: string;
    severity: string;
    description: string;
    category: string;
    start_line: number;
    end_line: number;
    remediation: string;
  }>;
  security_score: number;
  threat_score: number;
}

export interface CampaignResult {
  campaign_id: string;
  status: string;
}

export class ZaseonClient {
  private http: AxiosInstance;

  constructor(apiUrl: string, apiKey: string = "") {
    this.http = axios.create({
      baseURL: apiUrl,
      timeout: 120_000,
      headers: {
        "Content-Type": "application/json",
        ...(apiKey ? { Authorization: `Bearer ${apiKey}` } : {}),
      },
    });
  }

  async quickScan(source: string, fileName: string): Promise<QuickScanResult> {
    const resp = await this.http.post("/api/v1/quickscan", {
      source,
      file_name: fileName,
      scan_type: "smart_contract",
    });
    return resp.data;
  }

  async startCampaign(source: string, mode: string): Promise<CampaignResult> {
    const resp = await this.http.post("/api/v1/soul/campaigns", {
      source_type: "file_upload",
      contract_source: source,
      mode,
    });
    return resp.data;
  }

  async getCampaignStatus(campaignId: string): Promise<any> {
    const resp = await this.http.get(
      `/api/v1/soul/campaigns/${campaignId}/status`,
    );
    return resp.data;
  }

  async getCampaignFindings(campaignId: string): Promise<any[]> {
    const resp = await this.http.get(
      `/api/v1/soul/campaigns/${campaignId}/findings`,
    );
    return resp.data;
  }

  /** Request LLM-powered remediation suggestions for a finding. */
  async getRemediation(
    source: string,
    fileName: string,
    findingTitle: string,
    startLine: number,
    endLine: number,
  ): Promise<RemediationSuggestion[]> {
    const resp = await this.http.post("/api/v1/findings/remediate", {
      source,
      file_name: fileName,
      finding_title: findingTitle,
      start_line: startLine,
      end_line: endLine,
    });
    return resp.data.suggestions || [];
  }

  /** Request an LLM-powered explanation of a finding. */
  async explainFinding(
    source: string,
    snippet: string,
    findingTitle: string,
  ): Promise<FindingExplanation> {
    const resp = await this.http.post("/api/v1/findings/explain", {
      source,
      snippet,
      finding_title: findingTitle,
    });
    return resp.data;
  }
}

export interface RemediationSuggestion {
  title: string;
  description: string;
  patch_diff: string;
  confidence: number;
  gas_saved?: number;
}

export interface FindingExplanation {
  summary: string;
  impact: string;
  attack_scenario: string;
  recommendation: string;
  references: string[];
}
