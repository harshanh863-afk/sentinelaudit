import { useParams, useNavigate } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import { CheckCircle, Circle, Shield, Loader2, ArrowRight, AlertTriangle, Globe } from "lucide-react";
import { usePublicScanStatus } from "@/api/public";
import { Button } from "@/components/ui/button";

const PIPELINE_STAGES = [
  { id: "validating", label: "Target Validation", description: "Verifying URL and connectivity" },
  { id: "http", label: "HTTP Security Analysis", description: "Scanning security headers and cookies" },
  { id: "tls", label: "TLS Certificate Analysis", description: "Checking certificate and protocol security" },
  { id: "dns", label: "DNS Security Analysis", description: "Analyzing SPF, DMARC, DKIM, DNSSEC" },
  { id: "fingerprinting", label: "Technology Fingerprinting", description: "Detecting server and framework technologies" },
  { id: "javascript", label: "JavaScript Analysis", description: "Scanning for source maps, secrets, dangerous patterns" },
  { id: "rules", label: "Rule Processing", description: "Matching observations against security rules" },
  { id: "risk", label: "Risk Calculation", description: "Calculating risk scores and severity ratings" },
  { id: "compliance", label: "Compliance Assessment", description: "Evaluating compliance with 38+ frameworks" },
  { id: "report", label: "Report Generation", description: "Generating professional security report" },
];

function getCurrentStageIndex(currentStage: string, progress: number): number {
  if (!currentStage) return 0;
  const stage = currentStage.toLowerCase();
  const idx = PIPELINE_STAGES.findIndex((s) => stage.includes(s.id) || s.id.includes(stage));
  if (idx >= 0) return idx;
  return Math.min(Math.floor(progress / 10), PIPELINE_STAGES.length - 1);
}

function StageIcon({ stage, isActive, isDone }: { stage: typeof PIPELINE_STAGES[0]; isActive: boolean; isDone: boolean }) {
  if (isDone) return <CheckCircle className="h-6 w-6 text-security-low" />;
  if (isActive) return <Loader2 className="h-6 w-6 text-primary animate-spin" />;
  return <Circle className="h-6 w-6 text-muted-foreground/30" />;
}

export default function ScanProgress() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { data: scan, isLoading, error } = usePublicScanStatus(id);

  const isComplete = scan?.status === "completed";
  const isFailed = scan?.status === "failed";
  const progress = scan?.progress || 0;
  const currentStage = scan?.current_stage || "";
  const activeIndex = getCurrentStageIndex(currentStage, progress);

  if (isComplete) {
    navigate(`/report/${id}`, { replace: true });
    return null;
  }

  return (
    <div className="min-h-screen bg-background text-foreground flex flex-col">
      <nav className="border-b border-border/30 bg-background/80 backdrop-blur-xl">
        <div className="max-w-4xl mx-auto px-6 h-16 flex items-center gap-3">
          <div className="h-8 w-8 rounded-lg bg-gradient-to-br from-primary to-purple-600 flex items-center justify-center">
            <Shield className="h-5 w-5 text-white" />
          </div>
          <span className="font-bold">SentinelAudit</span>
          <span className="text-muted-foreground">—</span>
          <span className="text-sm text-muted-foreground truncate">{scan?.target_url || "Scanning..."}</span>
        </div>
      </nav>

      <div className="flex-1 flex items-center justify-center px-6 py-12">
        <div className="max-w-2xl w-full">
          {isLoading ? (
            <div className="flex flex-col items-center gap-4 py-20">
              <Loader2 className="h-12 w-12 text-primary animate-spin" />
              <p className="text-muted-foreground">Loading scan information...</p>
            </div>
          ) : isFailed ? (
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              className="glass-card p-12 text-center"
            >
              <AlertTriangle className="h-16 w-16 text-destructive mx-auto mb-6" />
              <h2 className="text-2xl font-bold mb-2">Scan Failed</h2>
              <p className="text-muted-foreground mb-6">{scan?.error || "The scan encountered an error and could not complete."}</p>
              <Button onClick={() => navigate("/")} className="gap-2">
                <ArrowRight className="h-4 w-4" /> Try Again
              </Button>
            </motion.div>
          ) : (
            <>
              {/* Scanner Animation */}
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="flex flex-col items-center mb-12"
              >
                <div className="relative mb-6">
                  <motion.div
                    className="absolute inset-0 rounded-full bg-primary/10"
                    animate={{ scale: [1, 1.4, 1], opacity: [0.3, 0.6, 0.3] }}
                    transition={{ duration: 2, repeat: Infinity, ease: "easeInOut" }}
                  />
                  <div className="relative h-24 w-24 rounded-full bg-gradient-to-br from-primary/20 via-purple-500/20 to-cyan-500/20 flex items-center justify-center glow-pulse">
                    <Shield className="h-12 w-12 text-primary" />
                  </div>
                </div>
                <motion.h1
                  className="text-2xl font-bold mb-2"
                  animate={{ opacity: [0.7, 1, 0.7] }}
                  transition={{ duration: 2, repeat: Infinity }}
                >
                  Security Assessment in Progress
                </motion.h1>
                <p className="text-muted-foreground text-center max-w-md">
                  Analyzing {scan?.target_url || "your target"} across 10 security dimensions
                </p>
              </motion.div>

              {/* Progress Bar */}
              <div className="mb-10">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium">{progress}% Complete</span>
                  <span className="text-xs text-muted-foreground">{currentStage || "Initializing..."}</span>
                </div>
                <div className="h-3 rounded-full bg-card overflow-hidden">
                  <motion.div
                    className="h-full rounded-full bg-gradient-to-r from-primary via-purple-500 to-cyan-500 progress-glow"
                    initial={{ width: "0%" }}
                    animate={{ width: `${progress}%` }}
                    transition={{ duration: 0.5, ease: "easeOut" }}
                  />
                </div>
              </div>

              {/* Pipeline Stages */}
              <div className="space-y-2">
                {PIPELINE_STAGES.map((stage, i) => {
                  const isDone = i < activeIndex;
                  const isActive = i === activeIndex;
                  return (
                    <motion.div
                      key={stage.id}
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: i * 0.03 }}
                      className={`glass-card p-4 flex items-center gap-4 transition-all duration-300 ${
                        isActive ? "border-primary/40 bg-primary/5" : isDone ? "border-security-low/20" : "opacity-40"
                      }`}
                    >
                      <StageIcon stage={stage} isActive={isActive} isDone={isDone} />
                      <div className="flex-1 min-w-0">
                        <p className={`font-medium text-sm ${isDone ? "text-security-low" : ""}`}>{stage.label}</p>
                        <p className="text-xs text-muted-foreground">{isActive ? stage.description : isDone ? "Complete" : "Pending"}</p>
                      </div>
                      {isActive && (
                        <motion.div
                          animate={{ opacity: [0.3, 1, 0.3] }}
                          transition={{ duration: 1.5, repeat: Infinity }}
                          className="h-2 w-2 rounded-full bg-primary"
                        />
                      )}
                    </motion.div>
                  );
                })}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
