import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDate(date: string | Date | null | undefined): string {
  if (!date) return "—";
  const d = new Date(date);
  return d.toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function severityColor(severity: string): string {
  const map: Record<string, string> = {
    critical: "#dc3545",
    high: "#fd7e14",
    medium: "#ffc107",
    low: "#28a745",
    info: "#17a2b8",
  };
  return map[severity.toLowerCase()] || "#6b7280";
}

export function severityLabel(severity: string): string {
  return severity.charAt(0).toUpperCase() + severity.slice(1);
}

export function riskRating(score: number): { label: string; color: string } {
  if (score >= 80) return { label: "Critical", color: "#dc3545" };
  if (score >= 60) return { label: "High", color: "#fd7e14" };
  if (score >= 40) return { label: "Medium", color: "#ffc107" };
  if (score >= 20) return { label: "Low", color: "#28a745" };
  return { label: "Info", color: "#17a2b8" };
}
