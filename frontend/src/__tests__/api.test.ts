import { describe, it, expect, vi, beforeEach } from "vitest";
import { api } from "@/api/client";

const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

describe("API client", () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  it("get returns parsed JSON", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ data: "test" }),
    });
    const result = await api.get("/test");
    expect(result).toEqual({ data: "test" });
    expect(mockFetch).toHaveBeenCalledWith("/api/v1/test", expect.any(Object));
  });

  it("post sends JSON body", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ id: "123" }),
    });
    const result = await api.post("/items", { name: "test" });
    expect(result).toEqual({ id: "123" });
    const call = mockFetch.mock.calls[0];
    expect(call[1].method).toBe("POST");
    expect(call[1].body).toBe(JSON.stringify({ name: "test" }));
  });

  it("throws on error response", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 404,
      text: async () => "Not Found",
    });
    await expect(api.get("/missing")).rejects.toThrow("API 404: Not Found");
  });

  it("returns undefined on 204", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 204,
      json: async () => { throw new Error("no body"); },
    });
    const result = await api.delete("/item/1");
    expect(result).toBeUndefined();
  });
});
