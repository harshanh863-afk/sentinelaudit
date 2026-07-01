import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { Toaster } from "@/components/ui/toaster";
import Landing from "@/pages/landing";
import ScanProgress from "@/pages/scan-progress";
import ReportViewer from "@/pages/report-viewer";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route path="/scan/:id" element={<ScanProgress />} />
        <Route path="/report/:id" element={<ReportViewer />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
      <Toaster />
    </BrowserRouter>
  );
}
