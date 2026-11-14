import { useState, useEffect } from "react";
import { analyzeMessageApi, analyzeUrlApi, analyzeScreenshotApi } from "./services/api";

const QUICK_TESTS = {
  message: [
    {
      label: "📈 WhatsApp Trading Bait",
      text: "Join our VIP trading group! Invest ₹100 and double your money in 24 hours. Check today's profit screenshot with 100% guaranteed returns.",
    },
    {
      label: "🧊 Frozen Withdrawal Scam",
      text: "Dear trader, your withdrawal is frozen due to high profit. Pay additional tax and release fee of ₹4,500 within 24 hours to unfreeze your full money.",
    },
    {
      label: "📲 RTO APK Malware",
      text: "RTO Traffic Alert: Unpaid e-Challan. Download and install RTO_Challan_2026.apk within 24 hours to avoid license suspension.",
    },
    {
      label: "💸 UPI Cashback Fraud",
      text: "Congratulations! You won ₹4,999 GPay cashback. Scan QR code or enter your UPI PIN to receive money immediately.",
    },
    {
      label: "💼 Fake WFH Task Job",
      text: "Dear candidate, part-time work from home openings. Like YouTube videos and earn ₹3,500 daily. Message our Telegram HR now.",
    },
    {
      label: "✅ Clean Message",
      text: "Hi David, thanks for following up. The project schedule has been finalized. Let us connect tomorrow at 10 AM.",
    },
  ],
  url: [
    { label: "📲 Direct .APK Link", text: "http://rto-echallan-update.xyz/RTO_Challan_2026.apk" },
    { label: "📈 Fake Broker Domain", text: "http://zerodha-vip-trading.top/login" },
    { label: "🚨 Typosquatted PayPal", text: "http://paypa1-account-verify.com/login" },
    { label: "✅ Official Zerodha", text: "https://zerodha.com" },
  ],
};

function RadialScoreGauge({ score, color }) {
  const clamped = Math.min(100, Math.max(0, score));
  const radius = 42;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (clamped / 100) * circumference;

  return (
    <div style={{ position: "relative", width: "108px", height: "108px", display: "flex", alignItems: "center", justifyContent: "center" }}>
      <svg width="108" height="108" style={{ transform: "rotate(-90deg)" }}>
        <circle
          cx="54"
          cy="54"
          r={radius}
          stroke="rgba(148, 163, 184, 0.14)"
          strokeWidth="9"
          fill="transparent"
        />
        <circle
          cx="54"
          cy="54"
          r={radius}
          stroke={color}
          strokeWidth="9"
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
          fill="transparent"
          style={{
            transition: "stroke-dashoffset 0.7s cubic-bezier(0.16, 1, 0.3, 1)",
            filter: `drop-shadow(0 0 8px ${color})`,
          }}
        />
      </svg>
      <div style={{ position: "absolute", textAlign: "center" }}>
        <div style={{ fontSize: "24px", fontWeight: "800", color, fontFamily: "'JetBrains Mono', monospace", lineHeight: 1 }}>
          {score}
        </div>
        <div style={{ fontSize: "10px", fontWeight: "700", color: "#64748b", marginTop: "3px" }}>/ 100</div>
      </div>
    </div>
  );
}

export default function App() {
  const [activeTab, setActiveTab] = useState("message");
  const [inputText, setInputText] = useState("");
  const [selectedFile, setSelectedFile] = useState(null);
  const [previewUrl, setPreviewUrl] = useState(null);
  const [loading, setLoading] = useState(false);
  const [slowWakeup, setSlowWakeup] = useState(false);
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
      // Ignore storage errors
    }
  }, []);

  const saveToHistory = (scanResult, targetInput) => {
    const entry = {
      id: Date.now(),
      timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
      type: activeTab,
      target: targetInput ? targetInput.slice(0, 48) + (targetInput.length > 48 ? "..." : "") : "Screenshot Scan",
      score: scanResult.risk_score,
      level: scanResult.risk_level,
    };
    const updated = [entry, ...history.slice(0, 11)];
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
    setSlowWakeup(false);
    setResult(null);

    const wakeupTimer = setTimeout(() => setSlowWakeup(true), 4500);

    try {
      let res;
      if (activeTab === "message") {
        if (!textToScan.trim()) throw new Error("Please enter a WhatsApp chat, SMS, or email body to analyze.");
        res = await analyzeMessageApi(textToScan);
        saveToHistory(res, textToScan);
      } else if (activeTab === "url") {
        if (!textToScan.trim()) throw new Error("Please enter a valid URL or APK link.");
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
      clearTimeout(wakeupTimer);
      setLoading(false);
      setSlowWakeup(false);
    }
  };

  const renderHighlightedText = (text, phrases = []) => {
    if (!phrases || phrases.length === 0) return text;
    const escaped = phrases
      .filter(Boolean)
      .sort((a, b) => b.length - a.length)
      .map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
      .join("|");
    if (!escaped) return text;
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
        bg: "rgba(239, 68, 68, 0.14)",
        border: "rgba(239, 68, 68, 0.45)",
        glow: "0 12px 36px -8px rgba(239, 68, 68, 0.32)",
        icon: "🚨",
        directive: "Block sender immediately. Do NOT install APKs, share UPI PIN/OTP, or pay withdrawal release fees.",
      };
    }
    if (level?.includes("SUSPICIOUS")) {
      return {
        color: "#f59e0b",
        bg: "rgba(245, 158, 11, 0.14)",
        border: "rgba(245, 158, 11, 0.45)",
        glow: "0 12px 36px -8px rgba(245, 158, 11, 0.26)",
        icon: "⚠️",
        directive: "High social-engineering risk. Verify independently via official app or website before acting.",
      };
    }
    if (level?.includes("CAUTION")) {
      return {
        color: "#eab308",
        bg: "rgba(234, 179, 8, 0.14)",
        border: "rgba(234, 179, 8, 0.45)",
        glow: "0 12px 36px -8px rgba(234, 179, 8, 0.22)",
        icon: "⚡",
        directive: "Exercise caution. Inspect sender domain and avoid clicking unverified links.",
      };
    }
    return {
      color: "#10b981",
      bg: "rgba(16, 185, 129, 0.14)",
      border: "rgba(16, 185, 129, 0.45)",
      glow: "0 12px 36px -8px rgba(16, 185, 129, 0.22)",
      icon: "🛡️",
      directive: "No known phishing, APK malware, or trading fraud patterns detected.",
    };
  };

  const downloadJSONReport = () => {
    if (!result) return;
    const reportData = {
      timestamp: new Date().toISOString(),
      scanner: "ScamShield SOC Engine v2.5",
      queryType: activeTab,
      ...result,
    };
    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `ScamShield-Dossier-${Date.now()}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const copyReportText = () => {
    if (!result) return;
    const cats = result.categories?.length ? `\nAttack Vectors: ${result.categories.join(", ")}` : "";
    const text = `🛡️ ScamShield Threat Dossier\nScore: ${result.risk_score}/100 (${result.risk_level})${cats}\nFindings:\n${(result.warnings || []).map((w) => `• ${w}`).join("\n")}`;
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div style={styles.appWrapper}>
      {/* Top SOC Navigation Bar */}
      <header style={styles.navbarWrap}>
        <nav style={styles.navbar}>
          <div style={styles.brandGroup}>
            <div style={styles.brandIconWrapper}>🛡️</div>
            <div>
              <div style={styles.brandTitleRow}>
                <span style={styles.brandTitle}>ScamShield</span>
                <span style={styles.versionTag}>v2.5 SOC</span>
              </div>
              <div style={styles.brandSub}>Multi-Vector Threat & OCR Intelligence</div>
            </div>
          </div>

          <div style={styles.navActions}>
            {history.length > 0 && (
              <button onClick={() => setShowHistory(!showHistory)} style={styles.historyBtn}>
                <span>🕒</span>
                <span>Log ({history.length})</span>
              </button>
            )}
            <div style={styles.statusIndicator}>
              <span className="status-pulse" style={styles.statusDot}></span>
              <span style={styles.statusText}>ACTIVE</span>
            </div>
          </div>
        </nav>
      </header>

      <main style={styles.mainContainer}>
        {/* Collapsible Triage Log Drawer */}
        {showHistory && (
          <section className="animate-dossier" style={styles.historyDrawer}>
            <div style={styles.historyHeader}>
              <span style={styles.sectionHeading}>Recent Triage Log</span>
              <button onClick={clearHistory} style={styles.clearBtn}>Clear Log</button>
            </div>
            <div style={styles.historyList}>
              {history.map((item) => (
                <div key={item.id} style={styles.historyItem}>
                  <div style={{ display: "flex", alignItems: "center", minWidth: 0, flex: 1 }}>
                    <span style={styles.historyType}>{item.type.toUpperCase()}</span>
                    <span style={styles.historyTarget}>{item.target}</span>
                  </div>
                  <div style={{ display: "flex", alignItems: "center", gap: "10px", flexShrink: 0 }}>
                    <span style={{ ...styles.historyScore, color: getThreatTheme(item.level).color }}>
                      {item.score}/100
                    </span>
                    <span style={styles.historyTime}>{item.timestamp}</span>
                  </div>
                </div>
              ))}
            </div>
          </section>
        )}

        {/* Hero Header */}
        <section style={styles.heroHeader}>
          <div style={styles.telemetryPill}>
            <span>⚡</span>
            <span>8 Heuristic Vectors • Dual-Pass OCR • Live URLhaus Intel</span>
          </div>
          <h1 style={styles.heroTitle}>
            Expose Scams Before <span style={styles.gradientText}>They Strike</span>
          </h1>
          <p style={styles.heroSubtitle}>
            Analyze WhatsApp trading traps, APK sideloading lures, UPI fraud, lookalike domains, and fake profit screenshots in seconds.
          </p>
        </section>

        {/* Segmented Mode Selector */}
        <div style={styles.tabBar}>
          <button
            onClick={() => { setActiveTab("message"); setResult(null); setError(null); }}
            style={{ ...styles.tabBtn, ...(activeTab === "message" ? styles.tabBtnActive : {}) }}
          >
            <span>✉️</span>
            <span>Chat / Email</span>
          </button>
          <button
            onClick={() => { setActiveTab("url"); setResult(null); setError(null); }}
            style={{ ...styles.tabBtn, ...(activeTab === "url" ? styles.tabBtnActive : {}) }}
          >
            <span>🌐</span>
            <span>URL / APK</span>
          </button>
          <button
            onClick={() => { setActiveTab("screenshot"); setResult(null); setError(null); }}
            style={{ ...styles.tabBtn, ...(activeTab === "screenshot" ? styles.tabBtnActive : {}) }}
          >
            <span>📷</span>
            <span>Screenshot OCR</span>
          </button>
        </div>

        {/* Interactive Demo Chips */}
        {QUICK_TESTS[activeTab] && (
          <div style={styles.chipsSection}>
            <div style={styles.chipsLabel}>Test Live Threat Vectors:</div>
            <div style={styles.chipsRow}>
              {QUICK_TESTS[activeTab].map((chip, idx) => (
                <button
                  key={idx}
                  className="chip-hover"
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
          </div>
        )}

        {/* Main Scanner Surface */}
        <div style={styles.inputCard}>
          {activeTab === "message" && (
            <div style={{ position: "relative" }}>
              <textarea
                rows={5}
                style={styles.textArea}
                placeholder="Paste suspicious WhatsApp message, Telegram trading group pitch, SMS alert, or email body..."
                value={inputText}
                onChange={(e) => setInputText(e.target.value)}
              />
              {inputText && (
                <button
                  onClick={() => { setInputText(""); setResult(null); }}
                  style={styles.clearInputBtn}
                  title="Clear text"
                >
                  ✕ Clear
                </button>
              )}
            </div>
          )}

          {activeTab === "url" && (
            <input
              type="text"
              style={styles.textInput}
              placeholder="e.g. http://zerodha-vip-trading.top/login or https://.../RTO.apk"
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
                <div style={styles.dropSub}>
                  Dual-pass OCR extracts text from fake trading dashboards, UPI receipts & banners
                </div>
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
                    ✕ Remove Screenshot
                  </button>
                </div>
              )}
            </div>
          )}

          <button
            onClick={() => handleScan()}
            disabled={loading}
            className={loading ? "btn-shimmer" : ""}
            style={{
              ...styles.analyzeBtn,
              cursor: loading ? "wait" : "pointer",
            }}
          >
            {loading
              ? slowWakeup
                ? "Waking Cloud Engine (Cold Start ~30s)..."
                : "Running Deep Heuristic Scan..."
              : "Evaluate Threat Payload"}
          </button>
        </div>

        {error && (
          <div className="animate-dossier" style={styles.errorAlert}>
            <span>⚠️</span>
            <span>{error}</span>
          </div>
        )}

        {/* Threat Intelligence Dossier */}
        {result && (
          <section
            className="animate-dossier"
            style={{
              ...styles.reportCard,
              borderColor: getThreatTheme(result.risk_level).border,
              boxShadow: getThreatTheme(result.risk_level).glow,
            }}
          >
            {/* Top Score + Verdict Header */}
            <div style={styles.reportHeader}>
              <div style={{ display: "flex", alignItems: "center", gap: "18px" }}>
                <RadialScoreGauge
                  score={result.risk_score}
                  color={getThreatTheme(result.risk_level).color}
                />
                <div>
                  <div style={styles.scoreLabel}>THREAT CONFIDENCE INDEX</div>
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
                  <p style={styles.directiveText}>
                    {getThreatTheme(result.risk_level).directive}
                  </p>
                </div>
              </div>
            </div>

            {/* Triggered Attack Vector Pills */}
            {result.categories?.length > 0 && (
              <div style={styles.vectorSection}>
                <div style={styles.sectionHeading}>Triggered Attack Vectors</div>
                <div style={styles.vectorRow}>
                  {result.categories.map((cat, idx) => (
                    <span key={idx} style={styles.vectorPill}>
                      ⚡ {cat}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Highlighted Payload Phrases */}
            {activeTab === "message" && result.matched_phrases?.length > 0 && (
              <div style={styles.highlightSection}>
                <div style={styles.sectionHeading}>Matched Forensic Indicators</div>
                <div style={styles.payloadBox}>
                  {renderHighlightedText(inputText, result.matched_phrases)}
                </div>
              </div>
            )}

            {/* Security Warnings List */}
            <div style={styles.warningsSection}>
              <div style={styles.sectionHeading}>Telemetry & Security Findings</div>
              <ul style={styles.warningList}>
                {result.warnings && result.warnings.length > 0 ? (
                  result.warnings.map((w, idx) => (
                    <li key={idx} style={styles.warningItem}>
                      <span style={{ color: getThreatTheme(result.risk_level).color, fontWeight: "700" }}>
                        ▸
                      </span>
                      <span>{w}</span>
                    </li>
                  ))
                ) : (
                  <li style={{ ...styles.warningItem, color: "#10b981" }}>
                    ✓ Payload passed all 8 heuristic checks with zero malicious indicators.
                  </li>
                )}
              </ul>
            </div>

            {/* Export & Copy Actions */}
            <div style={styles.actionBar}>
              <button onClick={downloadJSONReport} style={styles.actionBtn}>
                💾 Export JSON Dossier
              </button>
              <button onClick={copyReportText} style={styles.actionBtn}>
                {copied ? "✓ Copied to Clipboard" : "📋 Copy Incident Summary"}
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
  navbarWrap: { borderBottom: "1px solid rgba(148, 163, 184, 0.08)", backgroundColor: "rgba(5, 8, 16, 0.72)", backdropFilter: "blur(14px)", position: "sticky", top: 0, zIndex: 20 },
  navbar: { display: "flex", justifyContent: "space-between", alignItems: "center", padding: "12px 20px", maxWidth: "1040px", width: "100%", margin: "0 auto", gap: "12px" },
  brandGroup: { display: "flex", alignItems: "center", gap: "12px" },
  brandIconWrapper: { fontSize: "22px", background: "linear-gradient(135deg, rgba(56, 189, 248, 0.18), rgba(99, 102, 241, 0.18))", border: "1px solid rgba(56, 189, 248, 0.35)", padding: "8px 10px", borderRadius: "12px" },
  brandTitleRow: { display: "flex", alignItems: "center", gap: "8px" },
  brandTitle: { fontWeight: "800", fontSize: "18px", letterSpacing: "-0.4px", color: "#f8fafc" },
  versionTag: { fontSize: "10px", fontWeight: "700", fontFamily: "'JetBrains Mono', monospace", backgroundColor: "rgba(56, 189, 248, 0.14)", color: "#38bdf8", border: "1px solid rgba(56, 189, 248, 0.3)", padding: "2px 6px", borderRadius: "6px" },
  brandSub: { fontSize: "11px", color: "#64748b", fontWeight: "500", marginTop: "1px" },
  navActions: { display: "flex", alignItems: "center", gap: "8px" },
  historyBtn: { display: "flex", alignItems: "center", gap: "6px", background: "rgba(30, 41, 59, 0.65)", border: "1px solid rgba(148, 163, 184, 0.16)", color: "#e2e8f0", padding: "6px 12px", borderRadius: "999px", fontSize: "12px", fontWeight: "600", cursor: "pointer" },
  statusIndicator: { display: "flex", alignItems: "center", gap: "7px", background: "rgba(16, 185, 129, 0.1)", border: "1px solid rgba(16, 185, 129, 0.3)", padding: "6px 12px", borderRadius: "999px" },
  statusDot: { width: "7px", height: "7px", borderRadius: "50%", backgroundColor: "#10b981", boxShadow: "0 0 10px #10b981" },
  statusText: { fontSize: "10px", fontWeight: "800", color: "#10b981", letterSpacing: "0.6px" },
  mainContainer: { maxWidth: "820px", width: "100%", margin: "0 auto", padding: "18px 16px 56px 16px", flex: 1 },
  historyDrawer: { backgroundColor: "rgba(13, 20, 36, 0.94)", border: "1px solid rgba(148, 163, 184, 0.16)", borderRadius: "16px", padding: "16px", marginBottom: "20px", backdropFilter: "blur(16px)" },
  historyHeader: { display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "10px" },
  clearBtn: { background: "transparent", border: "none", color: "#f87171", fontSize: "12px", cursor: "pointer", fontWeight: "600" },
  historyList: { display: "flex", flexDirection: "column", gap: "8px", maxHeight: "220px", overflowY: "auto" },
  historyItem: { display: "flex", justifyContent: "space-between", alignItems: "center", gap: "10px", padding: "9px 12px", background: "#070b14", borderRadius: "8px", border: "1px solid rgba(148, 163, 184, 0.08)", fontSize: "12px" },
  historyType: { background: "rgba(56, 189, 248, 0.14)", color: "#38bdf8", padding: "2px 7px", borderRadius: "5px", fontSize: "10px", fontWeight: "700", marginRight: "8px", flexShrink: 0 },
  historyTarget: { color: "#cbd5e1", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" },
  historyScore: { fontWeight: "800", fontFamily: "'JetBrains Mono', monospace" },
  historyTime: { color: "#64748b", fontSize: "11px" },
  heroHeader: { textAlign: "center", margin: "12px 0 24px 0" },
  telemetryPill: { display: "inline-flex", alignItems: "center", gap: "6px", padding: "5px 12px", borderRadius: "999px", background: "rgba(56, 189, 248, 0.08)", border: "1px solid rgba(56, 189, 248, 0.22)", color: "#7dd3fc", fontSize: "11px", fontWeight: "600", marginBottom: "12px" },
  heroTitle: { fontSize: "clamp(26px, 5.5vw, 38px)", fontWeight: "800", lineHeight: "1.15", marginBottom: "10px", letterSpacing: "-0.8px" },
  gradientText: { background: "linear-gradient(135deg, #38bdf8 0%, #818cf8 100%)", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent" },
  heroSubtitle: { color: "#94a3b8", fontSize: "clamp(13px, 3.4vw, 15px)", lineHeight: "1.6", maxWidth: "620px", margin: "0 auto" },
  tabBar: { display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "6px", backgroundColor: "rgba(13, 20, 36, 0.78)", padding: "6px", borderRadius: "14px", border: "1px solid rgba(148, 163, 184, 0.12)", marginBottom: "14px", backdropFilter: "blur(14px)" },
  tabBtn: { display: "flex", alignItems: "center", justifyContent: "center", gap: "6px", padding: "11px 8px", backgroundColor: "transparent", border: "none", borderRadius: "10px", color: "#94a3b8", fontSize: "clamp(12px, 3vw, 14px)", fontWeight: "700", cursor: "pointer", transition: "all 0.2s ease", whiteSpace: "nowrap" },
  tabBtnActive: { background: "linear-gradient(135deg, #0284c7 0%, #2563eb 100%)", color: "#ffffff", boxShadow: "0 4px 14px rgba(2, 132, 199, 0.4)" },
  chipsSection: { marginBottom: "14px" },
  chipsLabel: { fontSize: "11px", fontWeight: "700", color: "#64748b", textTransform: "uppercase", letterSpacing: "0.5px", marginBottom: "7px" },
  chipsRow: { display: "flex", alignItems: "center", gap: "7px", flexWrap: "wrap" },
  chipBtn: { background: "rgba(15, 23, 42, 0.85)", border: "1px solid rgba(148, 163, 184, 0.16)", color: "#cbd5e1", padding: "6px 11px", borderRadius: "999px", fontSize: "12px", fontWeight: "600", cursor: "pointer", transition: "all 0.18s ease" },
  inputCard: { backgroundColor: "rgba(13, 20, 36, 0.82)", border: "1px solid rgba(148, 163, 184, 0.14)", backdropFilter: "blur(18px)", borderRadius: "18px", padding: "18px", display: "flex", flexDirection: "column", gap: "14px", boxShadow: "0 18px 40px -15px rgba(0, 0, 0, 0.6)" },
  textArea: { width: "100%", backgroundColor: "#070b14", border: "1px solid rgba(148, 163, 184, 0.14)", borderRadius: "12px", padding: "14px", color: "#f8fafc", fontSize: "14px", lineHeight: "1.65", resize: "vertical", outline: "none" },
  clearInputBtn: { position: "absolute", top: "10px", right: "10px", background: "rgba(30, 41, 59, 0.85)", border: "1px solid rgba(148, 163, 184, 0.2)", color: "#94a3b8", borderRadius: "6px", padding: "4px 8px", fontSize: "11px", fontWeight: "600", cursor: "pointer" },
  textInput: { width: "100%", backgroundColor: "#070b14", border: "1px solid rgba(148, 163, 184, 0.14)", borderRadius: "12px", padding: "14px", color: "#f8fafc", fontSize: "14px", fontFamily: "'JetBrains Mono', monospace", outline: "none" },
  dropZone: { border: "2px dashed rgba(56, 189, 248, 0.25)", borderRadius: "14px", backgroundColor: "#070b14", padding: "26px 16px", textAlign: "center", cursor: "pointer", transition: "all 0.2s ease" },
  dropZoneActive: { borderColor: "#38bdf8", backgroundColor: "rgba(56, 189, 248, 0.06)" },
  dropZoneContent: { cursor: "pointer", display: "flex", flexDirection: "column", alignItems: "center", gap: "6px" },
  uploadIcon: { fontSize: "32px", marginBottom: "2px" },
  dropTitle: { fontSize: "14px", fontWeight: "700", color: "#f8fafc" },
  dropSub: { fontSize: "12px", color: "#64748b", maxWidth: "420px" },
  previewContainer: { marginTop: "16px", display: "flex", flexDirection: "column", alignItems: "center", gap: "10px" },
  previewImg: { maxHeight: "190px", maxWidth: "100%", borderRadius: "10px", border: "1px solid rgba(148, 163, 184, 0.2)" },
  removeFileBtn: { background: "rgba(239, 68, 68, 0.16)", color: "#f87171", border: "1px solid rgba(239, 68, 68, 0.35)", padding: "6px 12px", borderRadius: "8px", fontSize: "12px", fontWeight: "600", cursor: "pointer" },
  analyzeBtn: { padding: "15px", background: "linear-gradient(135deg, #0284c7 0%, #2563eb 100%)", color: "#ffffff", border: "none", borderRadius: "12px", fontWeight: "700", fontSize: "15px", letterSpacing: "0.2px", boxShadow: "0 6px 20px rgba(2, 132, 199, 0.38)" },
  errorAlert: { marginTop: "16px", backgroundColor: "rgba(239, 68, 68, 0.12)", border: "1px solid rgba(239, 68, 68, 0.35)", padding: "13px 16px", borderRadius: "12px", color: "#fca5a5", fontSize: "13px", display: "flex", alignItems: "center", gap: "10px" },
  reportCard: { marginTop: "24px", backgroundColor: "rgba(13, 20, 36, 0.88)", backdropFilter: "blur(22px)", borderRadius: "18px", borderWidth: "1px", borderStyle: "solid", padding: "22px", display: "flex", flexDirection: "column", gap: "18px" },
  reportHeader: { display: "flex", justifyContent: "space-between", alignItems: "center", paddingBottom: "18px", borderBottom: "1px solid rgba(148, 163, 184, 0.1)" },
  scoreLabel: { fontSize: "11px", fontWeight: "700", color: "#64748b", letterSpacing: "0.6px", marginBottom: "6px" },
  riskBadge: { display: "inline-flex", alignItems: "center", gap: "8px", padding: "7px 14px", borderRadius: "999px", borderWidth: "1px", borderStyle: "solid", fontWeight: "800", fontSize: "13px", letterSpacing: "0.4px" },
  directiveText: { fontSize: "13px", color: "#cbd5e1", marginTop: "8px", lineHeight: "1.5" },
  vectorSection: { display: "flex", flexDirection: "column", gap: "8px" },
  vectorRow: { display: "flex", flexWrap: "wrap", gap: "8px" },
  vectorPill: { background: "rgba(239, 68, 68, 0.12)", border: "1px solid rgba(239, 68, 68, 0.3)", color: "#fca5a5", padding: "5px 11px", borderRadius: "8px", fontSize: "12px", fontWeight: "700" },
  highlightSection: { display: "flex", flexDirection: "column", gap: "8px" },
  sectionHeading: { fontSize: "11px", fontWeight: "700", color: "#94a3b8", textTransform: "uppercase", letterSpacing: "0.6px" },
  payloadBox: { backgroundColor: "#070b14", border: "1px solid rgba(148, 163, 184, 0.12)", padding: "14px", borderRadius: "12px", fontSize: "13.5px", lineHeight: "1.75", color: "#cbd5e1", maxHeight: "190px", overflowY: "auto" },
  highlightMark: { backgroundColor: "rgba(220, 38, 38, 0.85)", color: "#ffffff", padding: "2px 6px", borderRadius: "4px", fontWeight: "700" },
  warningsSection: { display: "flex", flexDirection: "column", gap: "8px" },
  warningList: { listStyleType: "none", display: "flex", flexDirection: "column", gap: "8px" },
  warningItem: { fontSize: "13.5px", color: "#e2e8f0", display: "flex", alignItems: "flex-start", gap: "10px", lineHeight: "1.55", background: "rgba(7, 11, 20, 0.6)", padding: "9px 12px", borderRadius: "9px", border: "1px solid rgba(148, 163, 184, 0.06)" },
  actionBar: { display: "flex", gap: "10px", paddingTop: "14px", borderTop: "1px solid rgba(148, 163, 184, 0.1)", flexWrap: "wrap" },
  actionBtn: { flex: 1, minWidth: "155px", padding: "11px 14px", backgroundColor: "#162036", color: "#e2e8f0", border: "1px solid rgba(148, 163, 184, 0.16)", borderRadius: "10px", fontSize: "12.5px", fontWeight: "700", cursor: "pointer" },
};