import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import GlobalError from "@/app/error";

describe("Error boundary page", () => {
  it("renders error message and retry button", () => {
    const reset = vi.fn();
    const error = new Error("Test error") as Error & { digest?: string };

    render(<GlobalError error={error} reset={reset} />);

    expect(screen.getByText("Something went wrong")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /try again/i }),
    ).toBeInTheDocument();
  });

  it("calls reset when retry is clicked", () => {
    const reset = vi.fn();
    const error = new Error("Test error") as Error & { digest?: string };

    render(<GlobalError error={error} reset={reset} />);
    fireEvent.click(screen.getByRole("button", { name: /try again/i }));

    expect(reset).toHaveBeenCalledOnce();
  });

  it("displays error digest when available", () => {
    const reset = vi.fn();
    const error = Object.assign(new Error("Test"), { digest: "abc123" });

    render(<GlobalError error={error} reset={reset} />);
    expect(screen.getByText(/abc123/)).toBeInTheDocument();
  });
});
