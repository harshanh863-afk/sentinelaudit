import { useQuery, useMutation } from "@tanstack/react-query";
import { api } from "./client";
import type { PublicScanResponse, PublicScanStatus, ProfessionalReport } from "@/types";

export function useStartPublicScan() {
  return useMutation({
    mutationFn: (target_url: string) =>
      api.post<PublicScanResponse>("/public/scan", { target_url }),
  });
}

export function usePublicScanStatus(scanId: string | undefined) {
  return useQuery<PublicScanStatus>({
    queryKey: ["public-scan", scanId],
    queryFn: () => api.get(`/public/scan/${scanId}`),
    enabled: !!scanId,
    refetchInterval: (query) => {
      const data = query.state.data;
      if (!data) return 2000;
      if (data.status === "completed" || data.status === "failed") return false;
      return 2000;
    },
  });
}

export function usePublicReport(scanId: string | undefined) {
  return useQuery<ProfessionalReport>({
    queryKey: ["public-report", scanId],
    queryFn: () => api.get(`/public/report/${scanId}`),
    enabled: !!scanId,
  });
}

export function getPublicReportUrl(scanId: string, format: "json" | "html" | "pdf"): string {
  return `/api/v1/public/report/${scanId}/download/${format}`;
}
