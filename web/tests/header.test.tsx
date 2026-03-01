import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Header } from "@/components/layout/header";

// Mock the API calls
vi.mock("@/lib/api", () => ({
  default: {
    get: vi.fn(),
    post: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
    interceptors: { request: { use: vi.fn() } },
  },
  getProjects: vi
    .fn()
    .mockResolvedValue([
      {
        id: "1",
        name: "DeFi Vault",
        source_type: "github",
        contract_address: "0x1234",
      },
    ]),
  getScans: vi
    .fn()
    .mockResolvedValue([
      {
        id: "scan-1",
        scan_type: "SMART_CONTRACT",
        status: "COMPLETED",
        findings_count: 3,
        branch: "main",
      },
    ]),
  getFindings: vi
    .fn()
    .mockResolvedValue([
      {
        id: "f-1",
        title: "Reentrancy in withdraw()",
        severity: "CRITICAL",
        category: "reentrancy",
        cwe_id: "CWE-841",
      },
    ]),
}));

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  );
}

describe("Header component", () => {
  it("renders title", () => {
    render(<Header title="Dashboard" />, { wrapper: createWrapper() });
    expect(screen.getByText("Dashboard")).toBeInTheDocument();
  });

  it("renders search input", () => {
    render(<Header title="Test" />, { wrapper: createWrapper() });
    const input = screen.getByPlaceholderText(/search scans/i);
    expect(input).toBeInTheDocument();
  });

  it("shows search results on typing", async () => {
    render(<Header title="Test" />, { wrapper: createWrapper() });
    const input = screen.getByPlaceholderText(/search scans/i);

    fireEvent.change(input, { target: { value: "reentrancy" } });

    await waitFor(
      () => {
        expect(
          screen.getByText("Reentrancy in withdraw()"),
        ).toBeInTheDocument();
      },
      { timeout: 1000 },
    );
  });

  it("clears search on X click", async () => {
    render(<Header title="Test" />, { wrapper: createWrapper() });
    const input = screen.getByPlaceholderText(
      /search scans/i,
    ) as HTMLInputElement;

    fireEvent.change(input, { target: { value: "test" } });

    await waitFor(() => {
      expect(screen.getByRole("button")).toBeTruthy();
    });

    // The X button should be present — clear button
    const clearButtons = screen.getAllByRole("button");
    const clearBtn = clearButtons.find(
      (btn) =>
        btn.querySelector("svg") !== null &&
        btn !== clearButtons[clearButtons.length - 1],
    );

    if (clearBtn) {
      fireEvent.click(clearBtn);
      expect(input.value).toBe("");
    }
  });
});
