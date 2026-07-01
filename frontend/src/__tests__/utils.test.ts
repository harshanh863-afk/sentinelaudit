import { describe, it, expect } from "vitest";
import { cn, formatDate, severityColor, severityLabel, riskRating } from "@/lib/utils";

describe("cn", () => {
  it("merges class names", () => {
    expect(cn("foo", "bar")).toBe("foo bar");
  });

  it("handles conditional classes", () => {
    expect(cn("base", false && "hidden", "visible")).toBe("base visible");
  });
});

describe("formatDate", () => {
  it("returns — for null", () => {
    expect(formatDate(null)).toBe("—");
  });

  it("formats date strings", () => {
    const result = formatDate("2024-06-15T10:30:00Z");
    expect(result).toContain("Jun");
    expect(result).toContain("2024");
  });
});

describe("severityColor", () => {
  it("returns correct colors", () => {
    expect(severityColor("critical")).toBe("#dc3545");
    expect(severityColor("high")).toBe("#fd7e14");
    expect(severityColor("medium")).toBe("#ffc107");
    expect(severityColor("low")).toBe("#28a745");
    expect(severityColor("info")).toBe("#17a2b8");
  });

  it("is case insensitive", () => {
    expect(severityColor("CRITICAL")).toBe("#dc3545");
  });
});

describe("severityLabel", () => {
  it("capitalizes first letter", () => {
    expect(severityLabel("critical")).toBe("Critical");
    expect(severityLabel("high")).toBe("High");
  });
});

describe("riskRating", () => {
  it("returns critical for score >= 80", () => {
    const r = riskRating(85);
    expect(r.label).toBe("Critical");
    expect(r.color).toBe("#dc3545");
  });

  it("returns high for score 60-79", () => {
    expect(riskRating(65).label).toBe("High");
  });

  it("returns medium for score 40-59", () => {
    expect(riskRating(50).label).toBe("Medium");
  });

  it("returns low for score 20-39", () => {
    expect(riskRating(30).label).toBe("Low");
  });

  it("returns info for score < 20", () => {
    expect(riskRating(10).label).toBe("Info");
  });
});
