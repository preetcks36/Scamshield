import { useState, useEffect } from "react";
import { analyzeMessageApi, analyzeUrlApi, analyzeScreenshotApi } from "./services/api";

const QUICK_TESTS = {
  message: [
    {
      label: "🚨 Netflix Phishing",
      text: "Hi Dear, Your Netflix account is on hold due to billing issues. Please update your payment details immediately within 24 hours: http://netflix-billing-update.xyz/login to avoid termination.",
    },
    {
      label: "⚡ Electricity Disconnection",
      text: "Dear consumer, your electricity power will be disconnected tonight at 9:30 PM because your previous month bill was not updated. Please immediately update payment details or call officer at 9876543210.",
    },
    {
      label: "📦 USPS Smish",
      text: "USPS Notification: Parcel #94001182 is on hold. Pay small redelivery fee of $1.50 immediately to avoid return: http://bit.ly/3xX-usps",
    },
    {
      label: "✅ Clean Message",
      text: "Hi David, thanks for following up. The project schedule has been finalized. Let us connect tomorrow at 10 AM.",
    },
  ],
  url: [
    { label: "🚨 Spoofed Netflix TLD", text: "http://netflix-security-update.xyz/signin" },
    { label: "🚨 Typosquatted Domain", text: "http://paypa1-account-verify.com/login" },
    { label: "⚠️ Obfuscated Link", text: "http://bit.ly/3xX-usps-delivery" },
    { label: "✅ Official Website", text: "https://www.netflix.com/browse" },
  ],
};

export default function App() {
  const [activeTab, setActiveTab] = useState("message");
  const [inputText, setInputText] = useState("");
  const [selectedFile, setSelectedFile] = useState(null);
  const [previewUrl, setPreviewUrl] = useState(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [isDragging, setIsDragging] = useState(false);
  const [copied, setCopied] = useState(false);
  const [history, setHistory] = useState([]);
  const [showHistory, setShowHistory] = useState(false);

  useEffect(() => {
    try {
      const saved = localStorage.getItem("scamshield_history");
      if (saved) setHistory(JSON.parse(saved));
    } catch {
      // Ignore storage parse errors
    }
  }, []);

  const saveToHistory = (scanResult, targetInput) => {
    const entry = {
      id: Date.now(),
      timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
      type: activeTab,
      target: targetInput ? targetInput.slice(0, 45) + (targetInput.length > 45 ? "..." : "") : "Screenshot Scan",
      score: scanResult.risk_score,
      level: scanResult.risk_level,
    };
    const updated = [entry, ...history.slice(0, 9)];
    setHistory(updated);
    try {
      localStorage.setItem("scamshield_history", JSON.stringify(updated));
    } catch {
      // Storage unavailable
    }
  };

  const clearHistory = () => {
    setHistory([]);
    try {
      localStorage.removeItem("scamshield_history");
    } catch {
      // Storage unavailable
    }
  };

  const handleFileSelect = (file) => {
    if (file && (file.type.startsWith("image/") || file.name.match(/\.(png|jpe?g|webp)$/i))) {
      setSelectedFile(file);
      setPreviewUrl(URL.createObjectURL(file));
      setResult(null);
      setError(null);
    } else {
      setError("Please upload a valid image file (PNG, JPG, or WEBP).");
    }
  };

  const handleScan = async (overrideInput) => {
    const textToScan = typeof overrideInput === "string" ? overrideInput : inputText;
    setError(null);
    setLoading(true);
    setResult(null);

    try {
      let res;
      if (activeTab === "message") {
        if (!textToScan.trim()) throw new Error("Please enter an SMS, email, or message body to analyze.");
        res = await analyzeMessageApi(textToScan);
        saveToHistory(res, textToScan);
      } else if (activeTab === "url") {
        if (!textToScan.trim()) throw new Error("Please enter a valid website URL.");
        res = await analyzeUrlApi(textToScan);
        saveToHistory(res, textToScan);
      } else if (activeTab === "screenshot") {
        if (!selectedFile) throw new Error("Please select or drop a screenshot image first.");
        res = await analyzeScreenshotApi(selectedFile);
        saveToHistory(res, selectedFile.name);
      }
      setResult(res);
    } catch (err) {
      setError(err.message || "Threat evaluation failed. Please verify API status.");
    } finally {
      setLoading(false);
    }
  };

  const renderHighlightedText = (text, phrases = []) => {
    if (!phrases || phrases.length === 0) return text;
    const escaped = phrases.map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|");
    const regex = new RegExp(`(${escaped})`, "gi");
    const parts = text.split(regex);

    return parts.map((part, i) =>
      phrases.some((p) => p.toLowerCase() === part.toLowerCase()) ? (
        <mark key={i} style={styles.highlightMark}>
          {part}
        </mark>
      ) : (
        part
      )
    );
  };

  const getThreatTheme = (level) => {
    if (level?.includes("CRITICAL")) {
      return {
        color: "#ef4444",
        bg: "rgba(239, 68, 68, 0.12)",
        border: "rgba(239, 68, 68, 0.4)",
        glow: "0 0 20px rgba(239, 68, 68, 0.25)",
        icon: "🚨",
      };
    }
    if (level?.includes("SUSPICIOUS")) {
      return {
        color: "#f59e0b",
        bg: "rgba(245, 158, 11, 0.12)",
        border: "rgba(245, 158, 11, 0.4)",
        glow: "0 0 20px rgba(245, 158, 11, 0.2)",
        icon: "⚠️",
      };
    }
    if (level?.includes("CAUTION")) {
      return {
        color: "#eab308",
        bg: "rgba(234, 179, 8, 0.12)",
        border: "rgba(234, 179, 8, 0.4)",
        glow: "0 0 20px rgba(234, 179, 8, 0.2)",
        icon: "⚡",
      };
    }
    return {
      color: "#10b981",
      bg: "rgba(16, 185, 129, 0.12)",
      border: "rgba(16, 185, 129, 0.4)",
      glow: "0 0 20px rgba(16, 185, 129, 0.2)",
      icon: "🛡️",
    };
  };

  const downloadJSONReport = () => {
    if (!result) return;
    const reportData = {
      timestamp: new Date().toISOString(),
      scanner: "ScamShield Security Engine v2.0",
      queryType: activeTab,
      ...result,
    };
    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `ScamShield-Report-${Date.now()}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const copyReportText = () => {
    if (!result) return;
    const text = `ScamShield Threat Analysis:\nRisk Score: ${result.risk_score}/100\nRisk Level: ${result.risk_level}\nWarnings:\n${(result.warnings || []).map((w) => `• ${w}`).join("\n")}`;
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div style={styles.appWrapper}>
      <nav style={styles.navbar}>
        <div style={styles.brandGroup}>
          <div style={styles.brandIconWrapper}>🛡️</div>
          <div>
            <div style={styles.brandTitle}>ScamShield</div>
            <div style={styles.brandSub}>AI & Heuristic SOC Gateway</div>
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          {history.length > 0 && (
            <button
              onClick={() => setShowHistory(!showHistory)}
              style={styles.historyBtn}
            >
              🕒 History ({history.length})
            </button>
          )}
          <div style={styles.statusIndicator}>
            <span style={styles.statusDot}></span>
            <span style={styles.statusText}>ENGINE ONLINE</span>
          </div>
        </div>
      </nav>

      <main style={styles.mainContainer}>
        {/* Collapsible History Drawer */}
        {showHistory && (
          <div style={styles.historyDrawer}>
            <div style={styles.historyHeader}>
              <span style={styles.sectionHeading}>Recent Triage Activity:</span>
              <button onClick={clearHistory} style={styles.clearBtn}>Clear All</button>
            </div>
            <div style={styles.historyList}>
              {history.map((item) => (
                <div key={item.id} style={styles.historyItem}>
                  <div>
                    <span style={styles.historyType}>{item.type.toUpperCase()}</span>
                    <span style={styles.historyTarget}>{item.target}</span>
                  </div>
                  <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                    <span style={{ ...styles.historyScore, color: getThreatTheme(item.level).color }}>
                      {item.score}/100
                    </span>
                    <span style={styles.historyTime}>{item.timestamp}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Hero Section */}
        <header style={styles.heroHeader}>
          <h1 style={styles.heroTitle}>
            Detect Phishing & Fraud <span style={styles.gradientText}>Instantly</span>
          </h1>
          <p style={styles.heroSubtitle}>
            Cross-examine unsolicited messages, verify domain anomalies, and process screenshot captures with dual-pass OCR.
          </p>
        </header>

        {/* Tab Selection */}
        <div style={styles.tabBar}>
          <button
            onClick={() => { setActiveTab("message"); setResult(null); setError(null); }}
            style={{ ...styles.tabBtn, ...(activeTab === "message" ? styles.tabBtnActive : {}) }}
          >
            ✉️ Email & SMS
          </button>
          <button
            onClick={() => { setActiveTab("url"); setResult(null); setError(null); }}
            style={{ ...styles.tabBtn, ...(activeTab === "url" ? styles.tabBtnActive : {}) }}
          >
            🌐 URL / Link
          </button>
          <button
            onClick={() => { setActiveTab("screenshot"); setResult(null); setError(null); }}
            style={{ ...styles.tabBtn, ...(activeTab === "screenshot" ? styles.tabBtnActive : {}) }}
          >
            📷 Screenshot OCR
          </button>
        </div>

        {/* Quick Test Demo Chips */}
        {QUICK_TESTS[activeTab] && (
          <div style={styles.chipsRow}>
            <span style={styles.chipsLabel}>Quick Demo:</span>
            {QUICK_TESTS[activeTab].map((chip, idx) => (
              <button
                key={idx}
                onClick={() => {
                  setInputText(chip.text);
                  handleScan(chip.text);
                }}
                style={styles.chipBtn}
              >
                {chip.label}
              </button>
            ))}
          </div>
        )}

        {/* Input Surface */}
        <div style={styles.inputCard}>
          {activeTab === "message" && (
            <textarea
              rows={5}
              style={styles.textArea}
              placeholder="Paste suspicious SMS notification, WhatsApp alert, or email body here..."
              value={inputText}
              onChange={(e) => setInputText(e.target.value)}
            />
          )}

          {activeTab === "url" && (
            <input
              type="text"
              style={styles.textInput}
              placeholder="e.g. http://netflix-billing-update.xyz/login"
              value={inputText}
              onChange={(e) => setInputText(e.target.value)}
            />
          )}

          {activeTab === "screenshot" && (
            <div
              onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
              onDragLeave={() => setIsDragging(false)}
              onDrop={(e) => {
                e.preventDefault();
                setIsDragging(false);
                if (e.dataTransfer.files?.[0]) handleFileSelect(e.dataTransfer.files[0]);
              }}
              style={{
                ...styles.dropZone,
                ...(isDragging ? styles.dropZoneActive : {}),
              }}
            >
              <input
                type="file"
                id="file-upload"
                style={{ display: "none" }}
                accept="image/png, image/jpeg, image/webp"
                onChange={(e) => e.target.files && handleFileSelect(e.target.files[0])}
              />
              <label htmlFor="file-upload" style={styles.dropZoneContent}>
                <div style={styles.uploadIcon}>📥</div>
                <div style={styles.dropTitle}>
                  {selectedFile ? selectedFile.name : "Tap to upload or drag & drop screenshot"}
                </div>
                <div style={styles.dropSub}>Supports PNG, JPG, or WEBP format</div>
              </label>

              {previewUrl && (
                <div style={styles.previewContainer}>
                  <img src={previewUrl} alt="Screenshot Preview" style={styles.previewImg} />
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      setSelectedFile(null);
                      setPreviewUrl(null);
                    }}
                    style={styles.removeFileBtn}
                  >
                    ✕ Remove Image
                  </button>
                </div>
              )}
            </div>
          )}

          <button
            onClick={() => handleScan()}
            disabled={loading}
            style={{
              ...styles.analyzeBtn,
              opacity: loading ? 0.7 : 1,
              cursor: loading ? "not-allowed" : "pointer",
            }}
          >
            {loading ? "Analyzing Vector Signatures..." : "Evaluate Payload"}
          </button>
        </div>

        {error && (
          <div style={styles.errorAlert}>
            <span>⚠️</span>
            <span>{error}</span>
          </div>
        )}

        {/* Threat Intelligence Report Card */}
        {result && (
          <section
            style={{
              ...styles.reportCard,
              borderColor: getThreatTheme(result.risk_level).border,
              boxShadow: getThreatTheme(result.risk_level).glow,
            }}
          >
            <div style={styles.reportHeader}>
              <div>
                <div style={styles.scoreLabel}>THREAT INDEX SCORE</div>
                <div style={styles.scoreNumberRow}>
                  <span
                    style={{
                      ...styles.scoreNumber,
                      color: getThreatTheme(result.risk_level).color,
                    }}
                  >
                    {result.risk_score}
                  </span>
                  <span style={styles.scoreTotal}>/ 100</span>
                </div>
              </div>

              <div
                style={{
                  ...styles.riskBadge,
                  color: getThreatTheme(result.risk_level).color,
                  backgroundColor: getThreatTheme(result.risk_level).bg,
                  borderColor: getThreatTheme(result.risk_level).border,
                }}
              >
                <span>{getThreatTheme(result.risk_level).icon}</span>
                <span>{result.risk_level}</span>
              </div>
            </div>

            {activeTab === "message" && result.matched_phrases?.length > 0 && (
              <div style={styles.highlightSection}>
                <div style={styles.sectionHeading}>Triggered Attack Phrases in Text:</div>
                <div style={styles.payloadBox}>
                  {renderHighlightedText(inputText, result.matched_phrases)}
                </div>
              </div>
            )}

            <div style={styles.warningsSection}>
              <div style={styles.sectionHeading}>Dossier Findings & Warnings:</div>
              <ul style={styles.warningList}>
                {result.warnings && result.warnings.length > 0 ? (
                  result.warnings.map((w, idx) => (
                    <li key={idx} style={styles.warningItem}>
                      <span style={{ color: getThreatTheme(result.risk_level).color, marginTop: "2px" }}>
                        ▶
                      </span>
                      <span>{w}</span>
                    </li>
                  ))
                ) : (
                  <li style={{ ...styles.warningItem, color: "#10b981" }}>
                    ✓ No recognized scam heuristics were triggered.
                  </li>
                )}
              </ul>
            </div>

            <div style={styles.actionBar}>
              <button onClick={downloadJSONReport} style={styles.actionBtn}>
                💾 Export JSON Dossier
              </button>
              <button onClick={copyReportText} style={styles.actionBtn}>
                {copied ? "✓ Copied!" : "📋 Copy Findings"}
              </button>
            </div>
          </section>
        )}
      </main>
    </div>
  );
}

const styles = {
  appWrapper: { minHeight: "100vh", display: "flex", flexDirection: "column" },
  navbar: { display: "flex", justifyContent: "space-between", alignItems: "center", padding: "16px 20px", maxWidth: "1000px", width: "100%", margin: "0 auto" },
  brandGroup: { display: "flex", alignItems: "center", gap: "12px" },
  brandIconWrapper: { fontSize: "24px", background: "rgba(14, 165, 233, 0.1)", border: "1px solid rgba(14, 165, 233, 0.3)", padding: "8px", borderRadius: "10px" },
  brandTitle: { fontWeight: "800", fontSize: "18px", letterSpacing: "-0.5px", color: "#f8fafc" },
  brandSub: { fontSize: "11px", color: "#64748b", fontWeight: "500" },
  statusIndicator: { display: "flex", alignItems: "center", gap: "8px", background: "rgba(16, 185, 129, 0.08)", border: "1px solid rgba(16, 185, 129, 0.25)", padding: "6px 12px", borderRadius: "999px" },
  statusDot: { width: "6px", height: "6px", borderRadius: "50%", backgroundColor: "#10b981", boxShadow: "0 0 8px #10b981" },
  statusText: { fontSize: "10px", fontWeight: "700", color: "#10b981", letterSpacing: "0.5px" },
  historyBtn: { background: "rgba(255, 255, 255, 0.05)", border: "1px solid rgba(255, 255, 255, 0.1)", color: "#cbd5e1", padding: "6px 12px", borderRadius: "8px", fontSize: "12px", fontWeight: "600", cursor: "pointer" },
  historyDrawer: { backgroundColor: "rgba(15, 23, 42, 0.95)", border: "1px solid rgba(255, 255, 255, 0.1)", borderRadius: "14px", padding: "14px", marginBottom: "20px", backdropFilter: "blur(12px)" },
  historyHeader: { display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "10px" },
  clearBtn: { background: "transparent", border: "none", color: "#ef4444", fontSize: "11px", cursor: "pointer", fontWeight: "600" },
  historyList: { display: "flex", flexDirection: "column", gap: "6px" },
  historyItem: { display: "flex", justifyContent: "space-between", alignItems: "center", padding: "8px 10px", background: "#060910", borderRadius: "6px", border: "1px solid rgba(255, 255, 255, 0.05)", fontSize: "12px" },
  historyType: { background: "#1e293b", color: "#38bdf8", padding: "2px 6px", borderRadius: "4px", fontSize: "10px", fontWeight: "700", marginRight: "8px" },
  historyTarget: { color: "#cbd5e1" },
  historyScore: { fontWeight: "700", fontFamily: "monospace" },
  historyTime: { color: "#64748b", fontSize: "11px" },
  mainContainer: { maxWidth: "780px", width: "100%", margin: "0 auto", padding: "16px 20px 48px 20px", flex: 1 },
  heroHeader: { textAlign: "center", margin: "16px 0 24px 0" },
  heroTitle: { fontSize: "clamp(24px, 5vw, 36px)", fontWeight: "800", lineHeight: "1.2", marginBottom: "10px", letterSpacing: "-0.7px" },
  gradientText: { background: "linear-gradient(135deg, #38bdf8 0%, #818cf8 100%)", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent" },
  heroSubtitle: { color: "#94a3b8", fontSize: "clamp(13px, 3.5vw, 15px)", lineHeight: "1.6", maxWidth: "600px", margin: "0 auto" },
  tabBar: { display: "flex", gap: "8px", backgroundColor: "rgba(15, 23, 42, 0.6)", padding: "6px", borderRadius: "14px", border: "1px solid rgba(255, 255, 255, 0.06)", marginBottom: "12px", backdropFilter: "blur(12px)" },
  tabBtn: { flex: 1, padding: "12px 10px", backgroundColor: "transparent", border: "none", borderRadius: "10px", color: "#94a3b8", fontSize: "clamp(12px, 3vw, 14px)", fontWeight: "600", cursor: "pointer", transition: "all 0.2s ease", whiteSpace: "nowrap" },
  tabBtnActive: { backgroundColor: "#0284c7", color: "#ffffff", boxShadow: "0 4px 12px rgba(2, 132, 199, 0.35)" },
  chipsRow: { display: "flex", alignItems: "center", gap: "6px", flexWrap: "wrap", marginBottom: "14px" },
  chipsLabel: { fontSize: "11px", fontWeight: "700", color: "#64748b", marginRight: "4px" },
  chipBtn: { background: "rgba(255, 255, 255, 0.05)", border: "1px solid rgba(255, 255, 255, 0.1)", color: "#cbd5e1", padding: "4px 10px", borderRadius: "999px", fontSize: "11px", fontWeight: "500", cursor: "pointer" },
  inputCard: { backgroundColor: "rgba(15, 23, 42, 0.75)", border: "1px solid rgba(255, 255, 255, 0.08)", backdropFilter: "blur(16px)", borderRadius: "16px", padding: "18px", display: "flex", flexDirection: "column", gap: "14px" },
  textArea: { width: "100%", backgroundColor: "#060910", border: "1px solid rgba(255, 255, 255, 0.1)", borderRadius: "12px", padding: "14px", color: "#f8fafc", fontSize: "14px", lineHeight: "1.6", resize: "vertical", outline: "none" },
  textInput: { width: "100%", backgroundColor: "#060910", border: "1px solid rgba(255, 255, 255, 0.1)", borderRadius: "12px", padding: "14px", color: "#f8fafc", fontSize: "14px", outline: "none" },
  dropZone: { border: "2px dashed rgba(255, 255, 255, 0.15)", borderRadius: "12px", backgroundColor: "#060910", padding: "24px 16px", textAlign: "center", cursor: "pointer", transition: "all 0.2s ease" },
  dropZoneActive: { borderColor: "#0284c7", backgroundColor: "rgba(2, 132, 199, 0.05)" },
  dropZoneContent: { cursor: "pointer", display: "flex", flexDirection: "column", alignItems: "center", gap: "6px" },
  uploadIcon: { fontSize: "30px", marginBottom: "4px" },
  dropTitle: { fontSize: "14px", fontWeight: "600", color: "#f8fafc" },
  dropSub: { fontSize: "12px", color: "#64748b" },
  previewContainer: { marginTop: "16px", display: "flex", flexDirection: "column", alignItems: "center", gap: "10px" },
  previewImg: { maxHeight: "180px", maxWidth: "100%", borderRadius: "8px", border: "1px solid rgba(255, 255, 255, 0.12)" },
  removeFileBtn: { background: "rgba(239, 68, 68, 0.15)", color: "#f87171", border: "1px solid rgba(239, 68, 68, 0.3)", padding: "6px 12px", borderRadius: "6px", fontSize: "12px", fontWeight: "600", cursor: "pointer" },
  analyzeBtn: { padding: "14px", background: "linear-gradient(135deg, #0284c7 0%, #2563eb 100%)", color: "#ffffff", border: "none", borderRadius: "12px", fontWeight: "700", fontSize: "15px", boxShadow: "0 4px 16px rgba(2, 132, 199, 0.35)", transition: "opacity 0.2s ease" },
  errorAlert: { marginTop: "16px", backgroundColor: "rgba(239, 68, 68, 0.1)", border: "1px solid rgba(239, 68, 68, 0.3)", padding: "12px 16px", borderRadius: "12px", color: "#f87171", fontSize: "13px", display: "flex", alignItems: "center", gap: "8px" },
  reportCard: { marginTop: "24px", backgroundColor: "rgba(15, 23, 42, 0.8)", backdropFilter: "blur(20px)", borderRadius: "16px", borderWidth: "1px", borderStyle: "solid", padding: "20px", display: "flex", flexDirection: "column", gap: "18px" },
  reportHeader: { display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "12px", paddingBottom: "16px", borderBottom: "1px solid rgba(255, 255, 255, 0.08)" },
  scoreLabel: { fontSize: "11px", fontWeight: "700", color: "#64748b", letterSpacing: "0.5px" },
  scoreNumberRow: { display: "flex", alignItems: "baseline", gap: "6px", marginTop: "4px" },
  scoreNumber: { fontSize: "36px", fontWeight: "900", lineHeight: "1", fontFamily: "'JetBrains Mono', monospace" },
  scoreTotal: { color: "#64748b", fontSize: "14px", fontWeight: "600" },
  riskBadge: { display: "flex", alignItems: "center", gap: "8px", padding: "8px 16px", borderRadius: "999px", borderWidth: "1px", borderStyle: "solid", fontWeight: "800", fontSize: "13px", letterSpacing: "0.4px" },
  highlightSection: { display: "flex", flexDirection: "column", gap: "8px" },
  sectionHeading: { fontSize: "12px", fontWeight: "700", color: "#94a3b8", textTransform: "uppercase", letterSpacing: "0.5px" },
  payloadBox: { backgroundColor: "#060910", border: "1px solid rgba(255, 255, 255, 0.08)", padding: "14px", borderRadius: "10px", fontSize: "13px", lineHeight: "1.7", color: "#cbd5e1", maxHeight: "180px", overflowY: "auto" },
  highlightMark: { backgroundColor: "#dc2626", color: "#ffffff", padding: "2px 6px", borderRadius: "4px", fontWeight: "600" },
  warningsSection: { display: "flex", flexDirection: "column", gap: "8px" },
  warningList: { listStyleType: "none", display: "flex", flexDirection: "column", gap: "8px" },
  warningItem: { fontSize: "13px", color: "#e2e8f0", display: "flex", alignItems: "flex-start", gap: "10px", lineHeight: "1.5" },
  actionBar: { display: "flex", gap: "10px", paddingTop: "12px", borderTop: "1px solid rgba(255, 255, 255, 0.08)", flexWrap: "wrap" },
  actionBtn: { flex: 1, minWidth: "150px", padding: "10px", backgroundColor: "#1e293b", color: "#cbd5e1", border: "1px solid rgba(255, 255, 255, 0.08)", borderRadius: "8px", fontSize: "12px", fontWeight: "600", cursor: "pointer" },
};