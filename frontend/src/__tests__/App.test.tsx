import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import App from "@/App";

vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
  ok: true,
  json: async () => ({}),
}));

function renderApp() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  });
  return render(
    <QueryClientProvider client={qc}>
      <App />
    </QueryClientProvider>
  );
}

describe("App", () => {
  it("renders the SentinelAudit heading", async () => {
    renderApp();
    expect(screen.getAllByText("SentinelAudit").length).toBeGreaterThanOrEqual(1);
  });

  it("renders the URL input", () => {
    renderApp();
    expect(screen.getByPlaceholderText("https://example.com")).toBeInTheDocument();
  });

  it("renders the Start Security Audit button", () => {
    renderApp();
    expect(screen.getByText("Start Security Audit")).toBeInTheDocument();
  });

  it("renders the How It Works section", () => {
    renderApp();
    expect(screen.getByText("How It Works")).toBeInTheDocument();
  });

  it("renders supported standards section", () => {
    renderApp();
    expect(screen.getByText("Supported Security Standards")).toBeInTheDocument();
  });
});
