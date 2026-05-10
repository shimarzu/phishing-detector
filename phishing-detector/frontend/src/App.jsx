import { useState, useEffect } from "react";
import "./App.css";

const API = "http://localhost:5000/api";

const SAMPLE_EMAILS = [
  {
    label: "Phishing: Bank alert",
    sender: "security@bank-alert-verification.xyz",
    subject: "URGENT: Your account has been suspended - Verify Now!",
    email: `Dear Valued Customer,

We have detected unusual activity on your bank account. Your account will be permanently suspended within 24 HOURS unless you verify your identity immediately!

Click here to verify your account now: http://bit.ly/secure-bank-verify-account

You must provide your account number, password, and social security number below to avoid suspension.

This is your FINAL WARNING. Act now before it's too late!!!

Security Department`,
  },
  {
    label: "Suspicious: Prize winner",
    sender: "noreply@lucky-winners-claim.top",
    subject: "Congratulations! You have been selected as our lottery winner",
    email: `Dear Lucky Winner,

Congratulations! You have won $50,000 in our international lottery!

To claim your prize, kindly respond with your full name and bank account details. This offer expires today!

Claim here: http://tinyurl.com/claim-prize-now

Best regards,
International Lottery Commission`,
  },
  {
    label: "Safe: Team meeting",
    sender: "john.smith@company.com",
    subject: "Team meeting rescheduled to Thursday",
    email: `Hi everyone,

Just a heads up that our weekly team meeting has been moved from Wednesday to Thursday at 2pm.

Please update your calendars. The agenda remains the same — sprint review and planning for next quarter.

Let me know if you have any conflicts.

Thanks,
John`,
  },
];

function ScoreRing({ score, size = 100 }) {
  const radius = 36;
  const circ = 2 * Math.PI * radius;
  const fill = (score / 100) * circ;
  const color = score >= 65 ? "#E24B4A" : score >= 35 ? "#EF9F27" : "#639922";
  return (
    <svg width={size} height={size} viewBox="0 0 100 100">
      <circle cx="50" cy="50" r={radius} fill="none" stroke="#e5e5e5" strokeWidth="8" />
      <circle
        cx="50" cy="50" r={radius} fill="none"
        stroke={color} strokeWidth="8"
        strokeDasharray={`${fill} ${circ}`}
        strokeLinecap="round"
        transform="rotate(-90 50 50)"
        style={{ transition: "stroke-dasharray 0.8s ease" }}
      />
      <text x="50" y="46" textAnchor="middle" fontSize="18" fontWeight="600" fill={color}>{score}</text>
      <text x="50" y="60" textAnchor="middle" fontSize="9" fill="#888">/ 100</text>
    </svg>
  );
}

function VerdictBadge({ verdict }) {
  const map = {
    phishing: { bg: "#FCEBEB", color: "#A32D2D", label: "Phishing Detected", icon: "⚠" },
    suspicious: { bg: "#FAEEDA", color: "#633806", label: "Suspicious", icon: "?" },
    safe: { bg: "#EAF3DE", color: "#27500A", label: "Likely Safe", icon: "✓" },
  };
  const v = map[verdict] || map.safe;
  return (
    <span style={{ background: v.bg, color: v.color, padding: "4px 12px", borderRadius: 8, fontWeight: 500, fontSize: 13 }}>
      {v.icon} {v.label}
    </span>
  );
}

function FindingRow({ finding }) {
  const sev = { high: "#FCEBEB", medium: "#FAEEDA", low: "#EAF3DE" };
  const sevText = { high: "#A32D2D", medium: "#633806", low: "#27500A" };
  return (
    <div className="finding-row">
      <span className="finding-cat">{finding.category}</span>
      <span className="finding-reason">{finding.reason || finding.url}</span>
      <span style={{ background: sev[finding.severity] || "#f5f5f5", color: sevText[finding.severity] || "#555", borderRadius: 6, padding: "2px 8px", fontSize: 11, fontWeight: 500, whiteSpace: "nowrap" }}>
        {finding.severity}
      </span>
    </div>
  );
}

function ScoreBar({ label, score }) {
  const color = score >= 65 ? "#E24B4A" : score >= 35 ? "#EF9F27" : "#639922";
  return (
    <div style={{ marginBottom: 10 }}>
      <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, color: "var(--text-secondary)", marginBottom: 4 }}>
        <span>{label}</span><span style={{ fontWeight: 500, color }}>{score}</span>
      </div>
      <div style={{ height: 6, background: "#e5e5e5", borderRadius: 4, overflow: "hidden" }}>
        <div style={{ width: `${score}%`, height: "100%", background: color, borderRadius: 4, transition: "width 0.7s ease" }} />
      </div>
    </div>
  );
}

export default function App() {
  const [sender, setSender] = useState("");
  const [subject, setSubject] = useState("");
  const [email, setEmail] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [history, setHistory] = useState([]);
  const [stats, setStats] = useState(null);
  const [activeTab, setActiveTab] = useState("scan");

  const fetchStats = async () => {
    try {
      const [s, h] = await Promise.all([
        fetch(`${API}/stats`).then(r => r.json()),
        fetch(`${API}/history`).then(r => r.json()),
      ]);
      setStats(s);
      setHistory(h.reverse());
    } catch {}
  };

  useEffect(() => { fetchStats(); }, [result]);

  const handleAnalyze = async () => {
    if (!email.trim() && !subject.trim() && !sender.trim()) {
      setError("Please enter at least some email content to analyze.");
      return;
    }
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const res = await fetch(`${API}/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sender, subject, email }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Analysis failed");
      setResult(data);
    } catch (e) {
      setError(e.message || "Could not connect to backend. Is Flask running?");
    } finally {
      setLoading(false);
    }
  };

  const loadSample = (s) => {
    setSender(s.sender);
    setSubject(s.subject);
    setEmail(s.email);
    setResult(null);
    setError("");
    setActiveTab("scan");
  };

  const clear = () => { setSender(""); setSubject(""); setEmail(""); setResult(null); setError(""); };

  return (
    <div className="app">
      <header className="header">
        <div className="header-inner">
          <div className="logo">
            <div className="logo-icon">⚡</div>
            <div>
              <div className="logo-title">PhishGuard</div>
              <div className="logo-sub">Email Threat Analyzer</div>
            </div>
          </div>
          <nav className="nav">
            <button className={`nav-btn ${activeTab === "scan" ? "active" : ""}`} onClick={() => setActiveTab("scan")}>Scan</button>
            <button className={`nav-btn ${activeTab === "history" ? "active" : ""}`} onClick={() => setActiveTab("history")}>History</button>
            <button className={`nav-btn ${activeTab === "about" ? "active" : ""}`} onClick={() => setActiveTab("about")}>About</button>
          </nav>
        </div>
      </header>

      <main className="main">
        {activeTab === "scan" && (
          <div className="scan-layout">
            <div className="panel">
              <div className="panel-header">
                <span className="panel-title">Analyze email</span>
                <button className="clear-btn" onClick={clear}>Clear</button>
              </div>

              <div className="samples-row">
                <span className="samples-label">Try a sample:</span>
                {SAMPLE_EMAILS.map((s, i) => (
                  <button key={i} className="sample-chip" onClick={() => loadSample(s)}>{s.label}</button>
                ))}
              </div>

              <div className="field">
                <label className="field-label">Sender</label>
                <input className="field-input" placeholder="e.g. alerts@paypal-security.xyz" value={sender} onChange={e => setSender(e.target.value)} />
              </div>
              <div className="field">
                <label className="field-label">Subject</label>
                <input className="field-input" placeholder="Email subject line" value={subject} onChange={e => setSubject(e.target.value)} />
              </div>
              <div className="field">
                <label className="field-label">Email body</label>
                <textarea className="field-textarea" placeholder="Paste the full email content here..." value={email} onChange={e => setEmail(e.target.value)} rows={9} />
              </div>

              {error && <div className="error-box">{error}</div>}

              <button className="analyze-btn" onClick={handleAnalyze} disabled={loading}>
                {loading ? <span className="spinner" /> : null}
                {loading ? "Analyzing..." : "Analyze email"}
              </button>
            </div>

            <div className="panel">
              {!result && !loading && (
                <div className="empty-state">
                  <div className="empty-icon">🛡</div>
                  <div className="empty-title">Results will appear here</div>
                  <div className="empty-sub">Paste an email and click analyze to detect phishing indicators</div>
                  {stats && (
                    <div className="mini-stats">
                      <div className="mini-stat"><div className="ms-num">{stats.total}</div><div className="ms-label">Scanned</div></div>
                      <div className="mini-stat danger"><div className="ms-num">{stats.phishing}</div><div className="ms-label">Phishing</div></div>
                      <div className="mini-stat warn"><div className="ms-num">{stats.suspicious}</div><div className="ms-label">Suspicious</div></div>
                      <div className="mini-stat safe"><div className="ms-num">{stats.safe}</div><div className="ms-label">Safe</div></div>
                    </div>
                  )}
                </div>
              )}
              {loading && (
                <div className="empty-state">
                  <div className="loading-dots"><span /><span /><span /></div>
                  <div className="empty-title">Scanning for threats...</div>
                </div>
              )}
              {result && (
                <div className="result-panel">
                  <div className="result-top">
                    <ScoreRing score={result.risk_score} size={90} />
                    <div>
                      <div className="result-score-label">Risk score</div>
                      <VerdictBadge verdict={result.verdict} />
                      <div className="result-meta">
                        {result.urls_found?.length > 0 && <span>{result.urls_found.length} URL{result.urls_found.length !== 1 ? "s" : ""} found</span>}
                        {result.findings?.length > 0 && <span>{result.findings.length} indicator{result.findings.length !== 1 ? "s" : ""} flagged</span>}
                      </div>
                    </div>
                  </div>

                  <div className="score-bars">
                    <ScoreBar label="URL risk" score={result.url_score} />
                    <ScoreBar label="Sender risk" score={result.sender_score} />
                    <ScoreBar label="Content risk" score={result.content_score} />
                  </div>

                  {result.findings?.length > 0 && (
                    <div>
                      <div className="section-label">Indicators found</div>
                      <div className="findings-list">
                        {result.findings.map((f, i) => <FindingRow key={i} finding={f} />)}
                      </div>
                    </div>
                  )}

                  {result.urls_found?.length > 0 && (
                    <div style={{ marginTop: 16 }}>
                      <div className="section-label">URLs extracted</div>
                      {result.urls_found.map((url, i) => (
                        <div key={i} className="url-pill">{url}</div>
                      ))}
                    </div>
                  )}

                  {result.findings?.length === 0 && (
                    <div className="safe-note">No phishing indicators found. This email appears safe.</div>
                  )}
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === "history" && (
          <div className="panel full-panel">
            <div className="panel-header">
              <span className="panel-title">Scan history</span>
              <span className="panel-count">{history.length} scan{history.length !== 1 ? "s" : ""}</span>
            </div>
            {history.length === 0 && (
              <div className="empty-state">
                <div className="empty-icon">📋</div>
                <div className="empty-title">No scans yet</div>
                <div className="empty-sub">Your scan history will appear here</div>
              </div>
            )}
            {history.map((item, i) => (
              <div key={i} className="history-row">
                <div className="history-left">
                  <VerdictBadge verdict={item.verdict} />
                  <div className="history-subject">{item.subject || "(No subject)"}</div>
                  <div className="history-sender">{item.sender || "(No sender)"}</div>
                </div>
                <div className="history-right">
                  <div className="history-score" style={{ color: item.risk_score >= 65 ? "#E24B4A" : item.risk_score >= 35 ? "#EF9F27" : "#639922" }}>
                    {item.risk_score}
                  </div>
                  <div className="history-time">{new Date(item.timestamp).toLocaleTimeString()}</div>
                </div>
              </div>
            ))}
          </div>
        )}

        {activeTab === "about" && (
          <div className="panel full-panel about-panel">
            <h2 className="about-title">How PhishGuard works</h2>
            <p className="about-text">PhishGuard analyzes emails across three threat vectors to compute a risk score from 0–100.</p>
            <div className="about-grid">
              {[
                { icon: "🔗", title: "URL analysis", desc: "Detects URL shorteners, IP-based links, suspicious TLDs, and brand impersonation in links." },
                { icon: "📨", title: "Sender analysis", desc: "Checks sender domain reputation, display name spoofing, and domain impersonation patterns." },
                { icon: "📝", title: "Content analysis", desc: "Scans for phishing keywords, urgency language, excessive capitalization, and sensitive info requests." },
              ].map((c, i) => (
                <div key={i} className="about-card">
                  <div className="about-card-icon">{c.icon}</div>
                  <div className="about-card-title">{c.title}</div>
                  <div className="about-card-desc">{c.desc}</div>
                </div>
              ))}
            </div>
            <div className="verdict-legend">
              <div className="vl-title">Verdict thresholds</div>
              <div className="vl-row"><span style={{ color: "#A32D2D", fontWeight: 500 }}>Phishing</span><span>Score ≥ 65 — high confidence threat</span></div>
              <div className="vl-row"><span style={{ color: "#633806", fontWeight: 500 }}>Suspicious</span><span>Score 35–64 — proceed with caution</span></div>
              <div className="vl-row"><span style={{ color: "#27500A", fontWeight: 500 }}>Safe</span><span>Score &lt; 35 — no significant threats found</span></div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
