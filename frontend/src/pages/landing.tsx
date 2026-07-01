import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { Shield, ArrowRight, Globe, Scan, FileText, CheckCircle, AlertTriangle, Lock, Server, Code, Cookie, Layers, Zap } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useStartPublicScan } from "@/api/public";

const fadeUp = {
  initial: { opacity: 0, y: 30 },
  whileInView: { opacity: 1, y: 0 },
  viewport: { once: true, margin: "-50px" },
  transition: { duration: 0.6 },
};

const stagger = {
  initial: { opacity: 0 },
  whileInView: { opacity: 1 },
  viewport: { once: true },
  transition: { staggerChildren: 0.1 },
};

function CyberGrid() {
  return (
    <div className="absolute inset-0 cyber-grid-bg pointer-events-none" />
  );
}

function FloatingCards() {
  const cards = [
    { icon: Shield, text: "TLS Security", x: "10%", y: "20%", delay: 0 },
    { icon: Lock, text: "HTTP Headers", x: "75%", y: "15%", delay: 0.5 },
    { icon: Server, text: "DNS Protection", x: "85%", y: "50%", delay: 1 },
    { icon: Code, text: "JS Analysis", x: "8%", y: "60%", delay: 1.5 },
  ];
  return (
    <div className="absolute inset-0 overflow-hidden pointer-events-none">
      {cards.map((c, i) => (
        <motion.div
          key={i}
          className="absolute glass-card px-4 py-2 flex items-center gap-2 float-up"
          style={{ left: c.x, top: c.y }}
          initial={{ opacity: 0, scale: 0.8 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: c.delay + 1, duration: 0.5 }}
        >
          <c.icon className="h-4 w-4 text-primary" />
          <span className="text-sm font-medium text-foreground/80">{c.text}</span>
        </motion.div>
      ))}
    </div>
  );
}

function ScanAnimation() {
  return (
    <div className="relative flex items-center justify-center">
      <motion.div
        className="absolute w-72 h-72 rounded-full border border-primary/20"
        animate={{ scale: [1, 1.3, 1], opacity: [0.3, 0.6, 0.3] }}
        transition={{ duration: 3, repeat: Infinity, ease: "easeInOut" }}
      />
      <motion.div
        className="absolute w-56 h-56 rounded-full border border-primary/30"
        animate={{ scale: [1, 1.2, 1], opacity: [0.4, 0.7, 0.4] }}
        transition={{ duration: 3, repeat: Infinity, ease: "easeInOut", delay: 0.5 }}
      />
      <motion.div
        className="w-40 h-40 rounded-full bg-gradient-to-br from-primary/20 via-purple-500/20 to-cyan-500/20 flex items-center justify-center"
        animate={{ boxShadow: ["0 0 30px rgba(139,92,246,0.2)", "0 0 60px rgba(139,92,246,0.4)", "0 0 30px rgba(139,92,246,0.2)"] }}
        transition={{ duration: 3, repeat: Infinity, ease: "easeInOut" }}
      >
        <Shield className="h-16 w-16 text-primary" />
      </motion.div>
    </div>
  );
}

const STEPS = [
  { icon: Globe, title: "Enter Website", desc: "Provide any public HTTPS website URL for assessment" },
  { icon: Scan, title: "Automated Security Assessment", desc: "Our scanners analyze headers, TLS, DNS, JavaScript, and more" },
  { icon: FileText, title: "Professional Security Report", desc: "Receive a detailed report with findings, compliance scores, and remediation" },
];

const CHECKS = [
  { icon: Shield, title: "Security Headers", desc: "CSP, HSTS, X-Frame-Options, and more" },
  { icon: Lock, title: "TLS Security", desc: "Certificate validity, protocol versions, cipher strength" },
  { icon: Server, title: "DNS Protection", desc: "SPF, DMARC, DKIM, DNSSEC, CAA records" },
  { icon: Code, title: "Technology Exposure", desc: "Server info, frameworks, infrastructure detection" },
  { icon: AlertTriangle, title: "JavaScript Security", desc: "Source maps, secrets, dangerous patterns" },
  { icon: Cookie, title: "Privacy Compliance", desc: "Cookie security, GDPR, CCPA, COPPA assessment" },
  { icon: Layers, title: "Security Standards", desc: "OWASP, NIST, ISO 27001, PCI DSS mapping" },
];

const STANDARDS = [
  "OWASP", "NIST", "ISO 27001", "PCI DSS", "SOC 2", "GDPR", "CCPA", "HIPAA",
  "MITRE ATT&CK", "CSA CCM", "FedRAMP", "COPPA",
];

export default function Landing() {
  const [url, setUrl] = useState("");
  const navigate = useNavigate();
  const { mutateAsync: startScan, isPending, error } = useStartPublicScan();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim() || isPending) return;
    try {
      const result = await startScan(url.trim());
      navigate(`/scan/${result.scan_id}`);
    } catch {
      // error displayed below input
    }
  };

  return (
    <div className="min-h-screen bg-background text-foreground overflow-hidden">
      {/* Nav */}
      <motion.nav
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        className="fixed top-0 left-0 right-0 z-50 border-b border-border/30 bg-background/80 backdrop-blur-xl"
      >
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="h-8 w-8 rounded-lg bg-gradient-to-br from-primary to-purple-600 flex items-center justify-center">
              <Shield className="h-5 w-5 text-white" />
            </div>
            <span className="font-bold text-lg tracking-tight">SentinelAudit</span>
          </div>
        </div>
      </motion.nav>

      {/* Hero */}
      <section className="relative min-h-screen flex items-center justify-center pt-16">
        <CyberGrid />
        <FloatingCards />
        <div className="relative z-10 max-w-4xl mx-auto px-6 text-center">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
            className="mb-8"
          >
            <ScanAnimation />
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.2 }}
          >
            <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full border border-primary/30 bg-primary/5 text-sm text-primary mb-6">
              <Zap className="h-4 w-4" />
              Professional Website Security Assessment
            </div>
            <h1 className="text-5xl md:text-7xl font-bold tracking-tight mb-6">
              <span className="text-gradient">SentinelAudit</span>
            </h1>
            <p className="text-xl md:text-2xl text-muted-foreground mb-4">
              Analyze security posture, compliance readiness, and privacy risks.
            </p>
          </motion.div>

          <motion.form
            onSubmit={handleSubmit}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.4 }}
            className="max-w-2xl mx-auto mt-10"
          >
            <div className="flex gap-3">
              <div className="relative flex-1">
                <Globe className="absolute left-4 top-1/2 -translate-y-1/2 h-5 w-5 text-muted-foreground" />
                <Input
                  type="url"
                  placeholder="https://example.com"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  className="h-14 pl-12 text-lg rounded-xl bg-card/50 border-border/50 focus:border-primary/50 backdrop-blur-sm"
                  required
                />
              </div>
              <Button
                type="submit"
                disabled={isPending || !url.trim()}
                className="h-14 px-8 rounded-xl text-lg gap-2 bg-gradient-to-r from-primary to-purple-600 hover:from-primary/90 hover:to-purple-600/90 shadow-lg shadow-primary/20"
              >
                {isPending ? (
                  <div className="h-5 w-5 animate-spin rounded-full border-2 border-white border-t-transparent" />
                ) : (
                  <Zap className="h-5 w-5" />
                )}
                {isPending ? "Analyzing..." : "Start Security Audit"}
              </Button>
            </div>
            {error && (
              <motion.p
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="mt-3 text-sm text-destructive"
              >
                {error instanceof Error ? error.message : "Failed to start scan. Please try again."}
              </motion.p>
            )}
          </motion.form>

          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 1, duration: 0.6 }}
            className="mt-8 flex items-center justify-center gap-6 text-sm text-muted-foreground"
          >
            <div className="flex items-center gap-1.5">
              <CheckCircle className="h-4 w-4 text-security-low" />
              Passive scanning
            </div>
            <div className="flex items-center gap-1.5">
              <CheckCircle className="h-4 w-4 text-security-low" />
              No exploitation
            </div>
            <div className="flex items-center gap-1.5">
              <CheckCircle className="h-4 w-4 text-security-low" />
              Anonymous
            </div>
          </motion.div>
        </div>

        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 1.5 }}
          className="absolute bottom-8 left-1/2 -translate-x-1/2"
        >
          <motion.div
            animate={{ y: [0, 8, 0] }}
            transition={{ duration: 2, repeat: Infinity }}
            className="text-muted-foreground/50"
          >
            <ArrowRight className="h-6 w-6 rotate-90" />
          </motion.div>
        </motion.div>
      </section>

      {/* How It Works */}
      <section className="relative py-32 px-6">
        <CyberGrid />
        <div className="max-w-6xl mx-auto">
          <motion.div {...fadeUp} className="text-center mb-16">
            <h2 className="text-4xl font-bold mb-4">How It Works</h2>
            <p className="text-lg text-muted-foreground">Three simple steps to a comprehensive security assessment</p>
          </motion.div>
          <motion.div {...stagger} className="grid md:grid-cols-3 gap-8">
            {STEPS.map((step, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, y: 30 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.15, duration: 0.5 }}
                className="glass-card-hover p-8 text-center relative"
              >
                <div className="absolute -top-4 -left-4 h-10 w-10 rounded-full bg-primary/20 flex items-center justify-center text-sm font-bold text-primary">
                  {i + 1}
                </div>
                <div className="h-16 w-16 rounded-2xl bg-gradient-to-br from-primary/20 to-purple-500/20 flex items-center justify-center mx-auto mb-6">
                  <step.icon className="h-8 w-8 text-primary" />
                </div>
                <h3 className="text-xl font-semibold mb-3">{step.title}</h3>
                <p className="text-muted-foreground">{step.desc}</p>
              </motion.div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* What We Check */}
      <section className="relative py-32 px-6 bg-gradient-to-b from-background via-primary/5 to-background">
        <CyberGrid />
        <div className="max-w-6xl mx-auto">
          <motion.div {...fadeUp} className="text-center mb-16">
            <h2 className="text-4xl font-bold mb-4">What SentinelAudit Checks</h2>
            <p className="text-lg text-muted-foreground">Comprehensive analysis across 7 security domains</p>
          </motion.div>
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
            {CHECKS.map((check, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.05, duration: 0.4 }}
                className="glass-card-hover p-6 group"
              >
                <div className="flex items-center gap-4 mb-4">
                  <div className="h-12 w-12 rounded-xl bg-gradient-to-br from-primary/20 to-purple-500/20 flex items-center justify-center group-hover:scale-110 transition-transform">
                    <check.icon className="h-6 w-6 text-primary" />
                  </div>
                  <h3 className="font-semibold text-lg">{check.title}</h3>
                </div>
                <p className="text-muted-foreground text-sm">{check.desc}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Supported Standards */}
      <section className="relative py-32 px-6">
        <CyberGrid />
        <div className="max-w-6xl mx-auto">
          <motion.div {...fadeUp} className="text-center mb-16">
            <h2 className="text-4xl font-bold mb-4">Supported Security Standards</h2>
            <p className="text-lg text-muted-foreground">Mapping findings to 38+ security frameworks and regulations</p>
          </motion.div>
          <motion.div {...stagger} className="flex flex-wrap justify-center gap-4">
            {STANDARDS.map((s, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, scale: 0.9 }}
                whileInView={{ opacity: 1, scale: 1 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.03 }}
                whileHover={{ scale: 1.05 }}
                className="glass-card px-6 py-3 rounded-xl border border-primary/20 font-semibold text-sm"
              >
                {s}
              </motion.div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* Trust Section */}
      <section className="relative py-32 px-6 bg-gradient-to-b from-background via-primary/5 to-background">
        <CyberGrid />
        <div className="max-w-4xl mx-auto">
          <motion.div {...fadeUp} className="text-center mb-12">
            <h2 className="text-4xl font-bold mb-4">Responsible Security Assessment</h2>
            <p className="text-lg text-muted-foreground">We believe in responsible security testing</p>
          </motion.div>
          <div className="grid md:grid-cols-2 gap-8">
            {[
              { icon: Shield, title: "Passive Assessment", desc: "All checks are read-only. We observe and report without exploitation." },
              { icon: AlertTriangle, title: "No Exploitation", desc: "We never attempt to exploit vulnerabilities. Findings are reported for remediation." },
              { icon: CheckCircle, title: "Responsible Testing", desc: "Our scanners follow ethical guidelines and responsible disclosure practices." },
              { icon: FileText, title: "Professional Reporting", desc: "Detailed reports with actionable remediation guidance for your security team." },
            ].map((item, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.1 }}
                className="glass-card-hover p-6 flex gap-4"
              >
                <div className="h-12 w-12 rounded-xl bg-gradient-to-br from-primary/20 to-purple-500/20 flex items-center justify-center shrink-0">
                  <item.icon className="h-6 w-6 text-primary" />
                </div>
                <div>
                  <h3 className="font-semibold mb-2">{item.title}</h3>
                  <p className="text-sm text-muted-foreground">{item.desc}</p>
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-border/30 py-8 px-6">
        <div className="max-w-6xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4 text-sm text-muted-foreground">
          <div className="flex items-center gap-2">
            <Shield className="h-4 w-4 text-primary" />
            <span className="font-semibold text-foreground">SentinelAudit</span>
          </div>
          <p>Professional Website Security Assessment — Passive, Anonymous, Professional</p>
        </div>
      </footer>
    </div>
  );
}
