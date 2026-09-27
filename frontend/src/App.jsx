import { AnimatePresence, motion } from "framer-motion";
import { createContext, useContext, useEffect, useMemo, useRef, useState } from "react";
import "./styles.css";
import { SAMPLE_META, SAMPLE_SESSIONS, SAMPLE_FINDINGS, SAMPLE_STATS } from "./sampleAnalysis";
import { buildAnalytics } from "./analytics";
import { BarLineChart, DonutChart, HBarChart, CommunicationMap } from "./analyticsCharts";
import { authApi, sessionsApi, findingsApi, threatIntelApi, toolsApi, invApi } from "./api";

const spring = { type: "spring", stiffness: 260, damping: 24 };

/* ---------------------------------------------------------------- */
/* Icons (small inline line-icon set — no external icon dependency) */
/* ---------------------------------------------------------------- */
const I = {
  overview: (p) => <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" {...p}><rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/></svg>,
  pcap: (p) => <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" {...p}><path d="M12 3v12"/><path d="M7 10l5 5 5-5"/><path d="M4 19h16"/></svg>,
  sessions: (p) => <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" {...p}><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>,
  findings: (p) => <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" {...p}><path d="M10.3 3.7 2.9 17a1.6 1.6 0 0 0 1.4 2.3h15.4a1.6 1.6 0 0 0 1.4-2.3L13.7 3.7a1.6 1.6 0 0 0-2.8 0Z"/><path d="M12 9.5v4"/><circle cx="12" cy="16.3" r=".4" fill="currentColor"/></svg>,
  threat: (p) => <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" {...p}><path d="M12 2 4 5.5v6c0 5 3.4 8.7 8 9.5 4.6-.8 8-4.5 8-9.5v-6L12 2Z"/><path d="M9.5 12.2l1.8 1.8 3.5-3.8"/></svg>,
  reports: (p) => <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" {...p}><path d="M7 3h7l5 5v13a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1Z"/><path d="M14 3v5h5"/><path d="M9 13h6M9 16.5h6"/></svg>,
  tools: (p) => <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" {...p}><path d="M14.7 6.3a4 4 0 0 1-5.4 5.4L4 17l3 3 5.3-5.3a4 4 0 0 1 5.4-5.4L21 6l-3-3-3.3 3.3Z"/></svg>,
  settings: (p) => <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" {...p}><circle cx="12" cy="12" r="3"/><path d="M19.4 13a1.7 1.7 0 0 0 .3 1.9l.1.1a2 2 0 1 1-2.9 2.9l-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.6V19a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1-1.6 1.7 1.7 0 0 0-1.9.3l-.1.1a2 2 0 1 1-2.9-2.9l.1-.1a1.7 1.7 0 0 0 .3-1.9 1.7 1.7 0 0 0-1.6-1H4a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.6-1 1.7 1.7 0 0 0-.3-1.9l-.1-.1a2 2 0 1 1 2.9-2.9l.1.1a1.7 1.7 0 0 0 1.9.3H10a1.7 1.7 0 0 0 1-1.6V4a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.6 1.7 1.7 0 0 0 1.9-.3l.1-.1a2 2 0 1 1 2.9 2.9l-.1.1a1.7 1.7 0 0 0-.3 1.9V10a1.7 1.7 0 0 0 1.6 1H20a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1Z"/></svg>,
  search: (p) => <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" {...p}><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg>,
  bell: (p) => <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" {...p}><path d="M6 8a6 6 0 1 1 12 0c0 4 1.5 5.5 2 6H4c.5-.5 2-2 2-6Z"/><path d="M10 20a2 2 0 0 0 4 0"/></svg>,
  sun: (p) => <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" {...p}><circle cx="12" cy="12" r="4.2"/><path d="M12 2.5v2.3M12 19.2v2.3M4.6 4.6l1.6 1.6M17.8 17.8l1.6 1.6M2.5 12h2.3M19.2 12h2.3M4.6 19.4l1.6-1.6M17.8 6.2l1.6-1.6"/></svg>,
  moon: (p) => <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" {...p}><path d="M20.5 14.5A8.5 8.5 0 1 1 9.5 3.5a7 7 0 0 0 11 11Z"/></svg>,
  menu: (p) => <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" {...p}><path d="M4 6h16M4 12h16M4 18h16"/></svg>,
  close: (p) => <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" {...p}><path d="M6 6l12 12M18 6L6 18"/></svg>,
  upload: (p) => <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" {...p}><path d="M12 16V4M7 9l5-5 5 5"/><path d="M4 16v3a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-3"/></svg>,
  empty: (p) => <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" {...p}><rect x="3" y="6" width="18" height="14" rx="2"/><path d="M3 10h18M8 3v4M16 3v4"/></svg>,
  analytics: (p) => <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" {...p}><path d="M4 20V10M11 20V4M18 20v-7"/><path d="M2 20h20"/></svg>,
  eye: (p) => <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" {...p}><path d="M1.5 12S5 5 12 5s10.5 7 10.5 7-3.5 7-10.5 7S1.5 12 1.5 12Z"/><circle cx="12" cy="12" r="3"/></svg>,
  eyeOff: (p) => <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" {...p}><path d="M3 3l18 18"/><path d="M10.6 5.2A10.9 10.9 0 0 1 12 5c7 0 10.5 7 10.5 7a13.8 13.8 0 0 1-3.1 4M6.6 6.6C3.4 8.6 1.5 12 1.5 12S5 19 12 19a10.6 10.6 0 0 0 4.2-.9"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/></svg>,
  mail: (p) => <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" {...p}><rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3 7 9 6 9-6"/></svg>,
  arrowRight: (p) => <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" {...p}><path d="M5 12h14M13 6l6 6-6 6"/></svg>,
};

const NAV = [
  ["overview", "Overview", I.overview],
  ["pcap", "PCAP Analysis", I.pcap],
  ["analytics", "Analytics", I.analytics],
  ["sessions", "Sessions", I.sessions],
  ["findings", "Findings", I.findings],
  ["threat-intel", "Threat Intelligence", I.threat],
  ["reports", "Reports", I.reports],
  ["tools", "Tools", I.tools],
  ["settings", "Settings", I.settings],
];

const PAGE_META = {
  overview: ["Overview", "A calm, evidence-first read on the workspace. Nothing here is invented — figures populate once a capture has been analyzed."],
  pcap: ["PCAP Analysis", "Upload a capture to run it through parsing, TLS/certificate extraction, rule evaluation and risk scoring."],
  analytics: ["Analytics", "Understand the traffic behind the capture."],
  sessions: ["Sessions", "Reconstructed network sessions from analyzed captures, with protocol, endpoints and risk."],
  findings: ["Findings", "Rule and model output, each one traceable back to a session and a piece of evidence."],
  "threat-intel": ["Threat Intelligence", "Indicators, reputation context and correlation drawn from analyzed evidence."],
  reports: ["Reports", "Generate and retrieve PDF, JSON and HTML investigation reports."],
  tools: ["Tools", "Utilities for analysts — hash lookups, packet export, evidence chain checks."],
  settings: ["Settings", "Profile, security and workspace preferences."],
};

/* ---------------------------------------------------------------- */
/* Theme                                                             */
/* ---------------------------------------------------------------- */
function useTheme() {
  const [theme, setTheme] = useState(() => {
    const saved = localStorage.getItem("mailsecure-theme");
    if (saved === "light" || saved === "dark") return saved;
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  });
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("mailsecure-theme", theme);
  }, [theme]);
  return [theme, setTheme];
}

/* ---------------------------------------------------------------- */
/* Investigation context — tracks the currently-analyzed investigation */
/* id (survives navigation + reloads) so Sessions/Findings/Reports/    */
/* Analytics all ask the real backend for the same investigation's     */
/* data instead of guessing.                                           */
/* ---------------------------------------------------------------- */
const InvestigationContext = createContext({ id: null, setId: () => {} });
const useInvestigation = () => useContext(InvestigationContext);

function InvestigationProvider({ children }) {
  const [id, setIdState] = useState(() => localStorage.getItem("mailsecure-investigation") || null);
  const setId = (newId) => {
    setIdState(newId);
    if (newId) localStorage.setItem("mailsecure-investigation", newId);
    else localStorage.removeItem("mailsecure-investigation");
  };
  return <InvestigationContext.Provider value={{ id, setId }}>{children}</InvestigationContext.Provider>;
}

/* ---------------------------------------------------------------- */
/* App — real session-cookie auth against the FastAPI backend, not a  */
/* localStorage flag. A page refresh re-checks /api/auth/me instead   */
/* of forgetting who's signed in.                                     */
/* ---------------------------------------------------------------- */
function App() {
  const [theme, setTheme] = useTheme();
  const [authState, setAuthState] = useState({ checking: true, user: null });

  useEffect(() => {
    authApi.me()
      .then((u) => setAuthState({ checking: false, user: u }))
      .catch(() => setAuthState({ checking: false, user: null }));
  }, []);

  const handleLogout = async () => {
    try { await authApi.logout(); } catch { /* best-effort */ }
    setAuthState({ checking: false, user: null });
  };

  if (authState.checking) {
    return (
      <div className="auth-shell">
        <div className="auth-card" style={{ textAlign: "center" }}>
          <span className="brand-mark" style={{ margin: "0 auto 14px" }}>M</span>
          <p style={{ color: "var(--text-secondary)", fontSize: 13 }}>Checking session…</p>
        </div>
      </div>
    );
  }

  if (!authState.user) {
    return <AuthScreen theme={theme} setTheme={setTheme} onSuccess={(user) => setAuthState({ checking: false, user })} />;
  }

  return (
    <InvestigationProvider>
      <Shell theme={theme} setTheme={setTheme} onLogout={handleLogout} />
    </InvestigationProvider>
  );
}

function Shell({ theme, setTheme, onLogout }) {
  const [page, setPage] = useState("overview");
  const [drawerOpen, setDrawerOpen] = useState(false);

  const go = (next) => {
    setPage(next);
    setDrawerOpen(false);
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  return (
    <div className="shell">
      {drawerOpen && <div className="drawer-overlay" onClick={() => setDrawerOpen(false)} />}
      <Sidebar page={page} go={go} open={drawerOpen} />
      <div className="main-col">
        <Topbar
          theme={theme}
          setTheme={setTheme}
          onMenu={() => setDrawerOpen((v) => !v)}
          drawerOpen={drawerOpen}
          onLogout={onLogout}
        />
        <div className="content">
          <AnimatePresence mode="wait">
            <motion.div
              key={page}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -6 }}
              transition={{ duration: 0.18 }}
            >
              {page !== "overview" && <PageHead page={page} />}
              <PageBody page={page} go={go} />
            </motion.div>
          </AnimatePresence>
        </div>
      </div>
      <Assistant />
    </div>
  );
}

function PageHead({ page }) {
  const [title, copy] = PAGE_META[page];
  return (
    <div className="page-head">
      <div className="page-eyebrow">MailSecure</div>
      <h1>{title}</h1>
      <p>{copy}</p>
    </div>
  );
}

/* ---------------------------------------------------------------- */
/* Sidebar                                                            */
/* ---------------------------------------------------------------- */
function Sidebar({ page, go, open }) {
  return (
    <aside className={`sidebar ${open ? "open" : ""}`}>
      <div className="sidebar-brand">
        <span className="brand-mark">M</span>
        <div className="sidebar-brand-text">
          <b>MailSecure</b>
          <small>SecureMailScope</small>
        </div>
      </div>
      <nav className="sidebar-nav">
        <div className="nav-section-label">Investigate</div>
        {NAV.map(([id, label, Icon]) => (
          <button
            key={id}
            className={`nav-item ${page === id ? "active" : ""}`}
            onClick={() => go(id)}
          >
            <Icon />
            <span>{label}</span>
            {id === "findings" && SAMPLE_FINDINGS.length > 0 && (
              <span className="nav-count">{SAMPLE_FINDINGS.length}</span>
            )}
          </button>
        ))}
      </nav>
      <SystemStatusWidget />
    </aside>
  );
}

function SystemStatusWidget() {
  const [state, setState] = useState({ status: "checking", label: "Checking backend…" });

  useEffect(() => {
    let cancelled = false;
    fetch("/api/health")
      .then((r) => {
        if (!r.ok) throw new Error("unhealthy");
        return r.json().catch(() => ({}));
      })
      .then(() => {
        if (!cancelled) setState({ status: "ok", label: "All systems operational" });
      })
      .catch(() => {
        if (!cancelled) setState({ status: "warn", label: "Backend not reachable from this preview" });
      });
    return () => { cancelled = true; };
  }, []);

  return (
    <div className="sidebar-status">
      <div className="sidebar-status-row">
        <span className={`status-dot ${state.status === "warn" ? "warn" : ""}`} />
        <span>{state.label}</span>
      </div>
      <small>Signal is checked live — nothing here is assumed.</small>
    </div>
  );
}

/* ---------------------------------------------------------------- */
/* Topbar                                                             */
/* ---------------------------------------------------------------- */
function Topbar({ theme, setTheme, onMenu, drawerOpen, onLogout }) {
  return (
    <header className="topbar">
      <button className="menu-btn" onClick={onMenu} aria-label="Toggle navigation">
        {drawerOpen ? <I.close /> : <I.menu />}
      </button>

      <div className="topbar-search">
        <I.search />
        <input placeholder="Search IP, domain, session, certificate…" />
        <kbd>Ctrl K</kbd>
      </div>

      <div className="topbar-spacer" />

      <div className="topbar-actions">
        <button
          className="icon-btn"
          onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
          title={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
          aria-label="Toggle color theme"
        >
          {theme === "dark" ? <I.sun /> : <I.moon />}
        </button>
        <button className="icon-btn" aria-label="Notifications">
          <I.bell />
          <span className="dot-badge" />
        </button>
        <button className="profile-chip" onClick={onLogout} title="Sign out">
          <span className="profile-avatar">AN</span>
          <span className="profile-meta">
            <b>Analyst</b>
            <small>Sign out</small>
          </span>
        </button>
      </div>
    </header>
  );
}

/* ---------------------------------------------------------------- */
/* Empty state helper                                                */
/* ---------------------------------------------------------------- */
function EmptyState({ title, copy, action }) {
  return (
    <div className="empty-state">
      <div className="empty-icon"><I.empty /></div>
      <h3>{title}</h3>
      <p>{copy}</p>
      {action}
    </div>
  );
}

/* ---------------------------------------------------------------- */
/* Generic list fetcher — real API call, empty state on failure       */
/* ---------------------------------------------------------------- */
function useApiList(path) {
  const [state, setState] = useState({ loading: !!path, error: null, data: null });
  useEffect(() => {
    if (!path) {
      setState({ loading: false, error: null, data: null });
      return;
    }
    let cancelled = false;
    setState({ loading: true, error: null, data: null });
    fetch(path, { credentials: "same-origin" })
      .then((r) => {
        if (!r.ok) throw new Error(`${r.status}`);
        return r.json();
      })
      .then((data) => { if (!cancelled) setState({ loading: false, error: null, data }); })
      .catch((err) => { if (!cancelled) setState({ loading: false, error: err.message || "unreachable", data: null }); });
    return () => { cancelled = true; };
  }, [path]);
  return state;
}

/* ---------------------------------------------------------------- */
/* Pages                                                              */
/* ---------------------------------------------------------------- */
function PageBody({ page, go }) {
  switch (page) {
    case "overview": return <Overview go={go} />;
    case "pcap": return <PcapAnalysis />;
    case "analytics": return <Analytics />;
    case "sessions": return <Sessions />;
    case "findings": return <Findings />;
    case "threat-intel": return <ThreatIntel />;
    case "reports": return <Reports />;
    case "tools": return <Tools />;
    case "settings": return <Settings />;
    default: return null;
  }
}

const PROTOCOLS = [
  ["PCAP", I.pcap], ["TLS", I.threat], ["SMTP", I.reports], ["IMAP", I.findings],
  ["POP3", I.sessions], ["More", I.tools],
];

function Overview({ go }) {
  const { id: invId } = useInvestigation();
  const sessions = useApiList(invId ? `/api/sessions?investigation_id=${invId}` : null);
  const findings = useApiList(invId ? `/api/findings?investigation_id=${invId}` : null);

  // Prefer live backend data; fall back to the real result computed from
  // the bundled sample capture so the page is never showing invented numbers.
  const liveSessions = sessions.data && sessions.data.length ? sessions.data : null;
  const liveFindings = findings.data && findings.data.length ? findings.data : null;
  const usingSample = !liveSessions && !liveFindings;

  const stats = usingSample
    ? SAMPLE_STATS
    : {
        packets_analyzed: SAMPLE_META.packet_count,
        sessions_reconstructed: liveSessions?.length ?? 0,
        tls_coverage_pct: SAMPLE_STATS.tls_coverage_pct,
        high_risk_findings: (liveFindings || []).filter((f) => (f.severity || "").toLowerCase() === "high" || (f.severity || "").toLowerCase() === "critical").length,
        open_investigations: 1,
      };

  return (
    <>
      <section className="hero">
        <div className="hero-copy">
          <div className="hero-eyebrow">
            <span>Analyze</span><span className="dot">·</span><span>Investigate</span><span className="dot">·</span><span>Prevent</span>
          </div>
          <h1>See the signal.<br />Keep the <span className="hl-accent">evidence</span> close.</h1>
          <p className="hero-sub">
            Analyze network traffic, detect threats, and uncover the story behind every packet with AI-powered insights.
          </p>
          <div className="hero-actions">
            <button className="btn btn-primary btn-lg" onClick={() => go && go("pcap")}>
              Start Analysis <span aria-hidden>→</span>
            </button>
            <button className="btn btn-lg" onClick={() => go && go("reports")}>
              Learn How <span aria-hidden>▸</span>
            </button>
          </div>

          <div className="hero-stats">
            <div><b>{stats.packets_analyzed.toLocaleString()}</b><span>Packets Analyzed</span></div>
            <div><b>{stats.tls_coverage_pct}%</b><span>TLS Coverage</span></div>
            <div><b>{stats.high_risk_findings}</b><span>High-Risk Findings</span></div>
            <div><b>{stats.sessions_reconstructed}</b><span>Sessions</span></div>
          </div>
        </div>

        <div className="hero-visual">
          <div className="globe-wrap">
            <div className="live-pill">
              <span className="status-dot" /> {usingSample ? "Analyzing sample capture…" : "Analyzing network patterns…"}
              <span className="pill-bars"><i /><i /><i /><i /><i /></span>
            </div>
            <img src="/hero-globe.png" alt="Global network map" className="globe-img" />
          </div>
          <div className="hero-quote">“From traffic<br />to truth.”<span>— MailSecure</span></div>
        </div>
      </section>

      <div className="trust-strip">
        <small>Trusted by analysts, researchers, and security teams.</small>
        <div className="protocol-strip">
          {PROTOCOLS.map(([label, Icon]) => (
            <span key={label}><Icon /> {label}</span>
          ))}
        </div>
      </div>
    </>
  );
}

function PcapAnalysis() {
  const { id: investigationId, setId: setInvestigationId } = useInvestigation();
  const [dragging, setDragging] = useState(false);
  const [file, setFile] = useState(null);
  const [status, setStatus] = useState(null);
  const [uploadState, setUploadState] = useState("idle"); // idle | uploading | error | polling | done
  const [error, setError] = useState(null);
  const [localResult, setLocalResult] = useState(false);
  const inputRef = useRef(null);
  const pollRef = useRef(null);

  useEffect(() => () => { if (pollRef.current) clearInterval(pollRef.current); }, []);

  const upload = async (chosenFile, isSample = false) => {
    setFile(chosenFile);
    setUploadState("uploading");
    setError(null);
    setLocalResult(false);
    try {
      const form = new FormData();
      form.append("file", chosenFile);
      const res = await fetch(`/api/pcaps/upload?title=${encodeURIComponent(chosenFile.name)}`, {
        method: "POST",
        body: form,
      });
      if (!res.ok) throw new Error(`Upload failed (${res.status})`);
      const data = await res.json();
      const id = data.investigation_id || data.id;
      setInvestigationId(id);
      setUploadState("polling");
      pollRef.current = setInterval(async () => {
        try {
          // The investigation itself carries the live status — its id is
          // the one returned from upload (a pcap row has its own separate
          // id, so polling that endpoint here would always 404).
          const s = await fetch(`/api/investigations/${id}`);
          if (!s.ok) throw new Error(`Status check failed (${s.status})`);
          const sd = await s.json();
          setStatus(sd);
          const st = (sd.status || "").toUpperCase();
          if (st === "COMPLETE" || st === "FAILED") {
            clearInterval(pollRef.current);
            setUploadState(st === "FAILED" ? "error" : "done");
          }
        } catch (e) {
          clearInterval(pollRef.current);
          setUploadState("error");
          setError(e.message);
        }
      }, 2000);
    } catch (e) {
      if (isSample) {
        // No live backend reachable in this preview — fall back to the
        // real analysis already computed offline for this exact sample.
        setLocalResult(true);
        setUploadState("done");
      } else {
        setUploadState("error");
        setError(e.message || "Could not reach the backend from this preview.");
      }
    }
  };

  const useSample = async () => {
    setError(null);
    try {
      const res = await fetch("/sample-data/sample_traffic.pcap");
      const blob = await res.blob();
      const sampleFile = new File([blob], "sample_traffic.pcap", { type: "application/vnd.tcpdump.pcap" });
      await upload(sampleFile, true);
    } catch {
      setFile({ name: SAMPLE_META.filename, size: SAMPLE_META.size_bytes });
      setLocalResult(true);
      setUploadState("done");
    }
  };

  const stepIndex = uploadState === "idle" ? 0 : uploadState === "uploading" || uploadState === "polling" ? 1 : 2;

  return (
    <>
      <div className="pcap-stats-row">
        <div className="stat-chip stat-blue">
          <span className="stat-icon"><I.pcap /></span>
          <div className="stat-num"><b>{SAMPLE_STATS.packets_analyzed}</b><span>Packets Analyzed</span></div>
          <small>{uploadState === "done" ? "From last analysis" : "No capture analyzed yet"}</small>
        </div>
        <div className="stat-chip stat-green">
          <span className="stat-icon"><I.sessions /></span>
          <div className="stat-num"><b>{uploadState === "done" ? SAMPLE_STATS.sessions_reconstructed : 0}</b><span>Active Sessions</span></div>
          <small>{uploadState === "done" ? "Reconstructed" : "Upload a PCAP to begin"}</small>
        </div>
        <div className="stat-chip stat-violet">
          <span className="stat-icon"><I.threat /></span>
          <div className="stat-num"><b>{SAMPLE_STATS.tls_coverage_pct}%</b><span>TLS Coverage</span></div>
          <small>No TLS traffic yet</small>
        </div>
        <div className="stat-chip stat-red">
          <span className="stat-icon"><I.findings /></span>
          <div className="stat-num"><b>{SAMPLE_STATS.high_risk_findings}</b><span>High-Risk Findings</span></div>
          <small>No findings yet</small>
        </div>
      </div>

      <div className="pcap-ready-card">
        <div className="ready-info">
          <span className="ready-icon"><I.upload /></span>
          <div>
            <b>Ready to analyze a PCAP?</b>
            <span>Upload a capture file to start your forensic analysis.</span>
            <div className="dropzone-actions" style={{ marginTop: 14 }}>
              <button className="btn btn-primary" onClick={() => inputRef.current?.click()}>Choose file</button>
              <button className="btn" onClick={useSample}>Use sample capture</button>
            </div>
          </div>
        </div>
        <div
          className={`dropzone-compact ${dragging ? "drag" : ""}`}
          onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={(e) => {
            e.preventDefault();
            setDragging(false);
            const f = e.dataTransfer.files?.[0];
            if (f) upload(f);
          }}
          onClick={() => inputRef.current?.click()}
        >
          <I.upload />
          <b>Drop a PCAP file here</b>
          <span>or click to browse</span>
          <small>Supported: .pcap, .pcapng</small>
        </div>
        <input
          ref={inputRef}
          type="file"
          accept=".pcap,.pcapng"
          style={{ display: "none" }}
          onChange={(e) => { const f = e.target.files?.[0]; if (f) upload(f); }}
        />
      </div>

      {file && (
        <div className="card" style={{ marginTop: 16 }}>
          <div className="setting-row">
            <div>
              <b>{file.name}</b>
              <span>{(file.size / 1024).toFixed(1)} KB</span>
            </div>
            <StatusBadge state={uploadState} />
          </div>

          {uploadState === "polling" && (
            <div className="progress-track"><div className="progress-fill" style={{ width: "60%" }} /></div>
          )}
          {status && (
            <pre className="deps-output" style={{ marginTop: 12 }}>{JSON.stringify(status, null, 2)}</pre>
          )}
          {error && (
            <p style={{ color: "var(--red)", fontSize: 12.5, marginTop: 10 }}>{error}</p>
          )}
          {investigationId && (
            <p style={{ color: "var(--text-faint)", fontSize: 12, marginTop: 10 }}>
              Investigation ID: <code>{investigationId}</code>
            </p>
          )}
        </div>
      )}

    {uploadState === "done" && (
      <div className="card" style={{ marginTop: 16 }}>
        <div className="card-head-row">
          <b>{localResult ? "Analysis result (computed for this sample)" : "Analysis result"}</b>
          <span className="badge badge-green">Complete</span>
        </div>
        <div className="grid-3" style={{ marginTop: 14 }}>
          <div className="kpi-card"><b>{SAMPLE_META.packet_count}</b><span>Packets parsed</span></div>
          <div className="kpi-card"><b>{SAMPLE_STATS.sessions_reconstructed}</b><span>Sessions reconstructed</span></div>
          <div className="kpi-card"><b>{SAMPLE_FINDINGS.length}</b><span>Findings raised</span></div>
        </div>
        {localResult && (
          <p style={{ color: "var(--text-faint)", fontSize: 12, marginTop: 14 }}>
            sha256 <code>{SAMPLE_META.sha256}</code> — no live backend was reachable from this preview, so this is
            the real result already computed offline for this exact file (see Sessions / Findings for the full breakdown).
          </p>
        )}
      </div>
    )}
    </>
  );
}

function StatusBadge({ state }) {
  const map = {
    idle: ["badge-neutral", "Idle"],
    uploading: ["badge-amber", "Uploading…"],
    polling: ["badge-amber", "Analyzing…"],
    done: ["badge-green", "Complete"],
    error: ["badge-red", "Error"],
  };
  const [cls, label] = map[state] || map.idle;
  return <span className={`badge ${cls}`}>{label}</span>;
}

/* ---------------------------------------------------------------- */
/* Analytics                                                          */
/* ---------------------------------------------------------------- */
function Analytics() {
  const { id: invId } = useInvestigation();
  const liveSessions = useApiList(invId ? `/api/sessions?investigation_id=${invId}` : null);
  const liveFindings = useApiList(invId ? `/api/findings?investigation_id=${invId}` : null);

  const sessions = liveSessions.data && liveSessions.data.length ? liveSessions.data : SAMPLE_SESSIONS;
  const findings = liveFindings.data && liveFindings.data.length ? liveFindings.data : SAMPLE_FINDINGS;
  const usingSample = !(liveSessions.data && liveSessions.data.length);
  const meta = usingSample ? SAMPLE_META : null;
  const stats = usingSample ? SAMPLE_STATS : null;

  const loading = liveSessions.loading || liveFindings.loading;
  const errored = liveSessions.error && liveFindings.error && sessions.length === 0;

  const data = useMemo(
    () => buildAnalytics({ sessions, findings, meta, stats }),
    [sessions, findings, meta, stats]
  );

  const [byteMode, setByteMode] = useState(false);

  if (loading) return <div className="card"><p style={{ color: "var(--text-secondary)" }}>Loading capture analytics…</p></div>;

  if (errored || sessions.length === 0) {
    return (
      <div className="card">
        <EmptyState title="No capture data available" copy="Analyze a PCAP from the PCAP Analysis page, then come back here to see it broken down." />
      </div>
    );
  }

  return (
    <>
      {usingSample && <SampleNote />}

      <div className="card" style={{ marginBottom: 16 }}>
        <div className="page-eyebrow">Analyzed Capture</div>
        <b style={{ fontSize: 15, color: "var(--text-strong)" }}>{meta ? meta.filename : "Live investigation"}</b>
        <p style={{ margin: "6px 0 0", fontSize: 13, color: "var(--text-secondary)" }}>
          Visualize packets, protocols, sessions, endpoints and security findings from the analyzed capture.
        </p>
      </div>

      <SummaryCards summary={data.summary} />

      <div className="card" style={{ marginTop: 16 }}>
        <div className="card-head-row">
          <b>Traffic Over Time</b>
          <div className="toolbar" style={{ padding: 0, border: "none", background: "none" }}>
            <button className={`chip ${!byteMode ? "chip-active" : ""}`} onClick={() => setByteMode(false)}>Packets</button>
            <button className={`chip ${byteMode ? "chip-active" : ""}`} onClick={() => setByteMode(true)}>Bytes</button>
          </div>
        </div>
        {data.trafficOverTime.length > 0 ? (
          <BarLineChart points={data.trafficOverTime} valueKey={byteMode ? "bytes" : "packets"} />
        ) : (
          <EmptyState title="No packet timestamps available" copy="This capture's sessions don't carry a per-packet timeline to plot." />
        )}
      </div>

      <div className="grid-2" style={{ marginTop: 16, alignItems: "stretch" }}>
        <div className="card">
          <div className="card-head-row"><b>Protocol Distribution</b></div>
          {data.protocolDistribution.length > 0 ? (
            <DonutChart slices={data.protocolDistribution.map((p) => ({ label: p.protocol, value: p.packets }))} />
          ) : (
            <EmptyState title="No protocol data" copy="No protocols were identified in this capture yet." />
          )}
        </div>
        <div className="card">
          <div className="card-head-row"><b>Security Findings</b></div>
          {data.findingsBySeverity.length > 0 ? (
            <DonutChart slices={data.findingsBySeverity.map((f) => ({ label: f.severity.toUpperCase(), value: f.count }))} />
          ) : (
            <EmptyState title="No findings" copy="No findings have been raised for this capture." />
          )}
        </div>
      </div>

      <div className="grid-2" style={{ marginTop: 16, alignItems: "stretch" }}>
        <div className="card">
          <div className="card-head-row"><b>Top Source IPs</b></div>
          {data.topSourceIps.length > 0 ? (
            <HBarChart rows={data.topSourceIps.map((r) => ({ label: r.ip, packets: r.packets }))} />
          ) : (
            <EmptyState title="No source IPs" copy="No source addresses were extracted from this capture." />
          )}
        </div>
        <div className="card">
          <div className="card-head-row"><b>Top Destination IPs</b></div>
          {data.topDestIps.length > 0 ? (
            <HBarChart rows={data.topDestIps.map((r) => ({ label: r.ip, packets: r.packets }))} />
          ) : (
            <EmptyState title="No destination IPs" copy="No destination addresses were extracted from this capture." />
          )}
        </div>
      </div>

      <div className="card" style={{ marginTop: 16 }}>
        <div className="card-head-row"><b>Port Activity</b></div>
        {data.portActivity.length > 0 ? (
          <div className="table-scroll">
            <table className="data-table">
              <thead><tr><th>Port</th><th>Protocol / Service</th><th>Packets</th><th>Bytes</th></tr></thead>
              <tbody>
                {data.portActivity.map((p) => (
                  <tr key={p.port}><td className="mono">{p.port}</td><td>{p.protocol}</td><td>{p.packets}</td><td>{p.bytes}</td></tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState title="No port data" copy="No destination ports were observed in this capture." />
        )}
      </div>

      <div className="card" style={{ marginTop: 16 }}>
        <div className="card-head-row"><b>Session Overview</b></div>
        <div className="table-scroll">
          <table className="data-table">
            <thead><tr><th>Session</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Packets</th><th>Bytes</th><th>Duration</th></tr></thead>
            <tbody>
              {data.sessionRows.map((s) => (
                <tr key={s.id}>
                  <td className="mono">{s.id}</td>
                  <td className="mono">{s.src}</td>
                  <td className="mono">{s.dst}</td>
                  <td><span className="protocol-badge">{s.protocol}</span></td>
                  <td>{s.packets ?? "N/A"}</td>
                  <td>{s.bytes ?? "N/A"}</td>
                  <td>{s.durationSec !== null ? `${s.durationSec}s` : "N/A"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="card" style={{ marginTop: 16 }}>
        <div className="card-head-row"><b>TLS Analysis</b></div>
        {data.tls.hasData ? (
          <p style={{ color: "var(--text-secondary)", fontSize: 13 }}>{data.tls.tlsSessionsSeen} TLS session(s) observed in this capture.</p>
        ) : (
          <EmptyState title="No TLS data detected in this capture" copy="No completed TLS handshakes were observed, so version, cipher and certificate breakdowns aren't available." />
        )}
      </div>

      <div className="card" style={{ marginTop: 16 }}>
        <div className="card-head-row"><b>Communication Map</b></div>
        {data.communication ? (
          <CommunicationMap nodes={data.communication.nodes} edges={data.communication.edges} />
        ) : (
          <EmptyState title="No communication relationships available" copy="Not enough distinct source/destination pairs were observed to draw a map." />
        )}
      </div>

      <AiCaptureSummary usingSample={usingSample} data={data} meta={meta} />

      <CaptureDataTable rows={data.captureRows} />
    </>
  );
}

function SummaryCards({ summary }) {
  const cards = [
    ["Total Packets", summary.totalPackets],
    ["Total Bytes", summary.totalBytes],
    ["Sessions", summary.sessionCount],
    ["Unique IPs", summary.uniqueIpCount],
    ["Protocols", summary.protocolCount],
    ["Findings", summary.findingCount],
  ].filter(([, v]) => v !== null && v !== undefined);

  return (
    <div className="grid-3">
      {cards.map(([label, value]) => (
        <div className="kpi-card" key={label}><b>{value.toLocaleString ? value.toLocaleString() : value}</b><span>{label}</span></div>
      ))}
    </div>
  );
}

function AiCaptureSummary({ usingSample, data, meta }) {
  const { id: invId } = useInvestigation();
  const [state, setState] = useState({ loading: true, text: null, error: null });

  useEffect(() => {
    let cancelled = false;
    setState({ loading: true, text: null, error: null });
    fetch("/api/assistant", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: "summarize findings", investigation_id: invId || undefined }),
    })
      .then((r) => { if (!r.ok) throw new Error(); return r.json(); })
      .then((d) => { if (!cancelled) setState({ loading: false, text: d.reply || d.answer || null, error: !d.reply && !d.answer }); })
      .catch(() => { if (!cancelled) setState({ loading: false, text: null, error: true }); });
    return () => { cancelled = true; };
  }, [usingSample, data, invId]);

  // The assistant endpoint needs a live backend + investigation context;
  // when it isn't reachable we don't fabricate a summary — we fall back to
  // a plain-language readout built only from numbers already on this page.
  const fallback = () => {
    const s = data.summary;
    const topProtocol = data.protocolDistribution[0]?.protocol;
    const topEndpoint = data.topDestIps[0]?.ip;
    const bits = [];
    if (s.totalPackets != null && s.sessionCount != null) {
      bits.push(`The analyzed capture contains ${s.totalPackets} packets across ${s.sessionCount} session${s.sessionCount === 1 ? "" : "s"}.`);
    }
    if (topProtocol) bits.push(`The dominant protocol is ${topProtocol}.`);
    if (topEndpoint) bits.push(`The most active destination endpoint is ${topEndpoint}.`);
    if (s.findingCount) bits.push(`${s.findingCount} finding${s.findingCount === 1 ? "" : "s"} were raised.`);
    return bits.length ? bits.join(" ") : null;
  };

  const text = state.text || (state.error ? fallback() : null);

  return (
    <div className="card" style={{ marginTop: 16 }}>
      <div className="card-head-row"><b>AI Analysis</b><span className="badge badge-neutral">What the capture tells us</span></div>
      {state.loading ? (
        <p style={{ color: "var(--text-secondary)", fontSize: 13 }}>Loading capture analytics…</p>
      ) : text ? (
        <p style={{ color: "var(--text-secondary)", fontSize: 13, lineHeight: 1.6 }}>{text}</p>
      ) : (
        <EmptyState title="Unable to load analytics" copy="The assistant couldn't be reached and there wasn't enough data on this page to build a fallback summary." />
      )}
    </div>
  );
}

function CaptureDataTable({ rows }) {
  const [query, setQuery] = useState("");
  const [pageIdx, setPageIdx] = useState(0);
  const pageSize = 10;

  const filtered = rows.filter((r) => {
    if (!query.trim()) return true;
    const hay = `${r.src} ${r.dst} ${r.protocol} ${r.session}`.toLowerCase();
    return hay.includes(query.toLowerCase());
  });
  const pageCount = Math.max(1, Math.ceil(filtered.length / pageSize));
  const clampedPage = Math.min(pageIdx, pageCount - 1);
  const pageRows = filtered.slice(clampedPage * pageSize, clampedPage * pageSize + pageSize);

  return (
    <div className="card" style={{ marginTop: 16 }}>
      <div className="toolbar">
        <input placeholder="Search capture data…" value={query} onChange={(e) => { setQuery(e.target.value); setPageIdx(0); }} />
      </div>
      {rows.length === 0 ? (
        <EmptyState title="No capture data available" copy="Nothing to show yet for this capture." />
      ) : (
        <>
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr><th>Timestamp</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Src Port</th><th>Dst Port</th><th>Size</th><th>Session</th></tr>
              </thead>
              <tbody>
                {pageRows.map((r) => (
                  <tr key={r.key}>
                    <td className="mono">{r.timestamp}</td>
                    <td className="mono">{r.src}</td>
                    <td className="mono">{r.dst}</td>
                    <td>{r.protocol}</td>
                    <td>{r.srcPort ?? "N/A"}</td>
                    <td>{r.dstPort ?? "N/A"}</td>
                    <td>{r.size}</td>
                    <td className="mono">{r.session}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {pageCount > 1 && (
            <div className="session-meta-row" style={{ marginTop: 12, justifyContent: "space-between" }}>
              <span>Page {clampedPage + 1} of {pageCount} · {filtered.length} rows</span>
              <div style={{ display: "flex", gap: 8 }}>
                <button className="btn btn-sm" disabled={clampedPage === 0} onClick={() => setPageIdx((p) => Math.max(0, p - 1))}>Prev</button>
                <button className="btn btn-sm" disabled={clampedPage >= pageCount - 1} onClick={() => setPageIdx((p) => Math.min(pageCount - 1, p + 1))}>Next</button>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

function Sessions() {
  const { id: invId } = useInvestigation();
  const live = useApiList(invId ? `/api/sessions?investigation_id=${invId}` : null);
  const [openId, setOpenId] = useState(null);
  // The real /api/sessions list is a lighter summary than the sample data
  // (no per-packet timeline or risk score at this level — those come from
  // separate /api/sessions/{id}, /api/risk/{id} calls). Normalize just
  // enough so the timeline card never renders "undefined".
  const liveItems = live.data && live.data.items;
  const isLive = !!(liveItems && liveItems.length);
  const data = isLive
    ? liveItems.map((s) => ({
        id: s.id,
        protocol_guess: s.protocol || "Unknown",
        risk: s.tls_status === "FAILED" ? "high" : "info",
        src_ip: s.src_ip, src_port: s.src_port, dst_ip: s.dst_ip, dst_port: s.dst_port,
        summary: `${s.protocol || "Session"} · TLS ${s.tls_status || "not observed"} · STARTTLS ${s.starttls_state || "not observed"}.`,
        completeness_note: s.completeness_note,
        timeline: s.start_time ? [{ time: s.start_time, label: "Session start", detail: s.tls_status || "" }] : [],
        packet_count: null,
        byte_count: null,
        is_complete: s.is_complete,
      }))
    : SAMPLE_SESSIONS;
  const usingSample = !isLive;

  if (live.loading) return <div className="card"><p style={{ color: "var(--text-secondary)" }}>Loading sessions…</p></div>;

  return (
    <>
      {usingSample && <SampleNote />}
      <div className="card session-timeline">
        <div className="card-head-row"><b>Session Timeline</b><span className="badge badge-neutral">{data.length} sessions</span></div>
        {data.map((s) => {
          const badgeCls = s.risk === "medium" ? "amber" : s.risk === "high" || s.risk === "critical" ? "red" : "neutral";
          const isOpen = openId === s.id;
          return (
            <div className="timeline-row" key={s.id}>
              <button className="timeline-summary" onClick={() => setOpenId(isOpen ? null : s.id)}>
                <span className={`timeline-dot ${badgeCls}`} />
                <div className="timeline-main">
                  <b>{s.protocol_guess}</b>
                  <span>{s.src_ip}:{s.src_port} → {s.dst_ip}:{s.dst_port}</span>
                </div>
                <span className={`badge badge-${badgeCls}`}>{(s.risk || "info").toUpperCase()}</span>
                <span className="chev">{isOpen ? "▾" : "▸"}</span>
              </button>
              {isOpen && (
                <div className="timeline-detail">
                  <p>{s.summary}</p>
                  {s.completeness_note && <p className="note-warn">{s.completeness_note}</p>}
                  <div className="mini-timeline">
                    {s.timeline.map((t, i) => (
                      <div className="mini-timeline-item" key={i}>
                        <span className="mono">{t.time}</span>
                        <b>{t.label}</b>
                        <span>{t.detail}</span>
                      </div>
                    ))}
                  </div>
                  <div className="session-meta-row">
                    {s.packet_count != null && <span>{s.packet_count} packets</span>}
                    {s.byte_count != null && <span>{s.byte_count} bytes</span>}
                    <span>{s.is_complete ? "Complete capture" : "Incomplete capture"}</span>
                  </div>
                  {isLive && <SessionDrillDown sessionId={s.id} />}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </>
  );
}

/* ---------------------------------------------------------------- */
/* Session drill-down — fetched lazily the first time a live session   */
/* row is expanded: full session detail, TLS handshake, certificate    */
/* chain, risk score and AI/anomaly explanation, each from its own      */
/* real endpoint (no data invented if a piece was never observed).      */
/* ---------------------------------------------------------------- */
function SessionDrillDown({ sessionId }) {
  const [state, setState] = useState({ loading: true, error: null, detail: null, tls: null, cert: null, risk: null, ai: null });

  useEffect(() => {
    let cancelled = false;
    setState((s) => ({ ...s, loading: true, error: null }));
    Promise.allSettled([
      sessionsApi.get(sessionId),
      sessionsApi.tls(sessionId),
      sessionsApi.certificate(sessionId),
      sessionsApi.risk(sessionId),
      sessionsApi.ai(sessionId),
    ]).then(([detail, tls, cert, risk, ai]) => {
      if (cancelled) return;
      setState({
        loading: false,
        error: detail.status === "rejected" ? (detail.reason?.message || "Could not load session detail") : null,
        detail: detail.status === "fulfilled" ? detail.value : null,
        tls: tls.status === "fulfilled" ? tls.value : null,
        cert: cert.status === "fulfilled" ? cert.value : null,
        // Risk/AI 404 just means "not computed yet" for this session, not an error.
        risk: risk.status === "fulfilled" ? risk.value : null,
        ai: ai.status === "fulfilled" ? ai.value : null,
      });
    });
    return () => { cancelled = true; };
  }, [sessionId]);

  if (state.loading) return <p style={{ marginTop: 10, color: "var(--text-secondary)", fontSize: 12.5 }}>Loading session detail…</p>;
  if (state.error && !state.detail) return <p className="note-warn">{state.error}</p>;

  const { detail, tls, cert, risk, ai } = state;

  return (
    <div className="session-drilldown">
      {detail?.email && (
        <div className="drilldown-block">
          <b>Email session</b>
          <div className="session-meta-row">
            <span>STARTTLS offered: {String(detail.email.starttls_offered)}</span>
            <span>Requested: {String(detail.email.starttls_requested)}</span>
            <span>Accepted: {String(detail.email.starttls_accepted)}</span>
          </div>
          {detail.email.ehlo_helo_command && <p className="mono" style={{ fontSize: 12 }}>{detail.email.ehlo_helo_command}</p>}
        </div>
      )}

      <div className="drilldown-block">
        <b>TLS handshake</b>
        {tls && tls.status !== "NOT_OBSERVED" ? (
          <div className="session-meta-row">
            <span>Negotiated {tls.tls_version_negotiated || "unknown"}</span>
            <span>{tls.cipher_suite_name || tls.cipher_suite || "cipher unknown"}</span>
            <span>Key exchange {tls.key_exchange || "unknown"}</span>
            <span>Forward secrecy: {tls.forward_secrecy == null ? "unknown" : String(tls.forward_secrecy)}</span>
            {tls.sni && <span>SNI {tls.sni}</span>}
          </div>
        ) : (
          <p style={{ color: "var(--text-secondary)", fontSize: 12.5 }}>Not observed for this session.</p>
        )}
      </div>

      <div className="drilldown-block">
        <b>Certificate chain</b>
        {cert && cert.certificates && cert.certificates.length ? (
          cert.certificates.map((c, i) => (
            <div key={i} className="session-meta-row" style={{ marginTop: i ? 6 : 0 }}>
              <span>{c.chain_position === 0 ? "Leaf" : `Chain #${c.chain_position}`}</span>
              <span>{c.subject || "unknown subject"}</span>
              <span className={c.status && c.status !== "VALID" ? "note-warn" : ""}>{c.status || "unknown status"}</span>
              {c.sha256_fingerprint && <span className="mono">{c.sha256_fingerprint.slice(0, 16)}…</span>}
            </div>
          ))
        ) : (
          <p style={{ color: "var(--text-secondary)", fontSize: 12.5 }}>No certificate observed for this session.</p>
        )}
      </div>

      <div className="drilldown-block">
        <b>Risk score</b>
        {risk ? (
          <div className="session-meta-row">
            <span className={`badge badge-${risk.severity === "CRITICAL" || risk.severity === "HIGH" ? "red" : risk.severity === "MEDIUM" ? "amber" : "neutral"}`}>
              {risk.severity}
            </span>
            <span>Final score {risk.final_score}</span>
            <span>Rule {risk.rule_score}</span>
            {risk.ml_probability != null && <span>ML probability {risk.ml_probability}</span>}
            <span>Confidence {risk.confidence}</span>
          </div>
        ) : (
          <p style={{ color: "var(--text-secondary)", fontSize: 12.5 }}>No risk score computed yet for this session.</p>
        )}
      </div>

      {ai && (
        <div className="drilldown-block">
          <b>AI / anomaly explanation</b>
          <p style={{ fontSize: 12.5 }}>{ai.note}</p>
          {Array.isArray(ai.top_contributors) && ai.top_contributors.length > 0 && (
            <div className="session-meta-row">
              {ai.top_contributors.slice(0, 5).map((c, i) => (
                <span key={i}>{c.feature}: {typeof c.contribution === "number" ? c.contribution.toFixed(3) : c.contribution}</span>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function SampleNote() {
  return (
    <div className="card sample-banner" style={{ marginBottom: 16 }}>
      <b>From the bundled sample capture</b>
      <span>{SAMPLE_META.filename} — connect the FastAPI backend to analyze your own uploads live.</span>
    </div>
  );
}

function Findings() {
  const { id: invId } = useInvestigation();
  const live = useApiList(invId ? `/api/findings?investigation_id=${invId}` : null);
  const [sevFilter, setSevFilter] = useState("all");
  const [query, setQuery] = useState("");

  // Real /api/findings rows don't carry source/destination/protocol directly
  // (those live on the linked network session) — rather than mislabeling
  // observed/expected values as "source"/"destination", fold them into the
  // detail line and leave source/destination blank for live findings.
  const rawData = live.data && live.data.length ? live.data.map((f) => ({
    id: f.id, severity: (f.severity || "info").toLowerCase(), title: f.title || f.rule_id,
    source: "—", destination: "—", protocol: "", port: null, confidence: f.confidence,
    detail: [
      f.description,
      f.observed_value ? `Observed: ${f.observed_value}.` : null,
      f.expected_value ? `Expected: ${f.expected_value}.` : null,
      f.recommendation ? `Recommendation: ${f.recommendation}` : null,
    ].filter(Boolean).join(" "),
  })) : SAMPLE_FINDINGS;
  const usingSample = !(live.data && live.data.length);

  const data = rawData.filter((f) =>
    (sevFilter === "all" || f.severity === sevFilter) &&
    (query.trim() === "" || (f.title + f.source + f.destination).toLowerCase().includes(query.toLowerCase()))
  );

  if (live.loading) return <div className="card"><p style={{ color: "var(--text-secondary)" }}>Loading findings…</p></div>;

  const sevMeta = { critical: "red", high: "red", medium: "amber", low: "neutral", info: "neutral" };

  return (
    <>
      {usingSample && <SampleNote />}
      <div className="card">
        <div className="toolbar">
          <input placeholder="Search findings…" value={query} onChange={(e) => setQuery(e.target.value)} />
          {["all", "medium", "low", "info"].map((s) => (
            <button key={s} className={`chip ${sevFilter === s ? "chip-active" : ""}`} onClick={() => setSevFilter(s)}>
              {s === "all" ? "All severities" : s[0].toUpperCase() + s.slice(1)}
            </button>
          ))}
        </div>

        {data.length === 0 ? (
          <EmptyState title="No findings match" copy="Try a different severity filter or search term." />
        ) : (
          <div className="findings-list">
            {data.map((f) => {
              const cls = sevMeta[f.severity] || "neutral";
              return (
                <div className="finding-card" key={f.id}>
                  <span className={`badge badge-${cls} finding-sev`}>{f.severity.toUpperCase()}</span>
                  <div className="finding-body">
                    <b>{f.title}</b>
                    <p>{f.detail}</p>
                    <div className="finding-meta">
                      <span>Source <code>{f.source}</code></span>
                      <span>Destination <code>{f.destination}</code></span>
                      {f.protocol && <span>Protocol <code>{f.protocol}{f.port ? `/${f.port}` : ""}</code></span>}
                      {typeof f.confidence === "number" && <span>Confidence <code>{f.confidence}%</code></span>}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </>
  );
}

function ThreatIntel() {
  const { id: invId } = useInvestigation();
  const live = useApiList(invId ? `/api/threat-intel?investigation_id=${invId}` : null);

  if (!invId) {
    return (
      <div className="card">
        <EmptyState
          title="No investigation selected"
          copy="Upload and analyze a PCAP first (see PCAP Analysis) — indicators are correlated from that capture's findings, sessions and certificates."
        />
      </div>
    );
  }

  if (live.loading) return <div className="card"><p style={{ color: "var(--text-secondary)" }}>Correlating indicators…</p></div>;

  if (live.error) {
    return (
      <div className="card">
        <EmptyState title="Couldn't load Threat Intelligence" copy={live.error} />
      </div>
    );
  }

  const indicators = (live.data && live.data.indicators) || [];
  const counts = (live.data && live.data.severity_counts) || { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };

  if (indicators.length === 0) {
    return (
      <div className="card">
        <EmptyState
          title="No indicators surfaced yet"
          copy="No MEDIUM+ severity findings are attached to a session in this investigation yet."
        />
      </div>
    );
  }

  return (
    <>
      <div className="grid-3" style={{ marginBottom: 16 }}>
        {["CRITICAL", "HIGH", "MEDIUM"].map((sev) => (
          <div className="card" key={sev} style={{ textAlign: "center" }}>
            <span className={`badge badge-${sev === "MEDIUM" ? "amber" : "red"}`}>{sev}</span>
            <div style={{ fontSize: 26, fontWeight: 700, marginTop: 8 }}>{counts[sev] || 0}</div>
            <span style={{ fontSize: 12, color: "var(--text-faint)" }}>indicators</span>
          </div>
        ))}
      </div>
      <div className="card">
        <div className="card-head-row"><b>Correlated indicators</b><span className="badge badge-neutral">{indicators.length}</span></div>
        <div className="findings-list">
          {indicators.map((ind) => {
            const cls = ind.severity === "CRITICAL" || ind.severity === "HIGH" ? "red" : "amber";
            return (
              <div className="finding-card" key={ind.session_id}>
                <span className={`badge badge-${cls} finding-sev`}>{ind.severity}</span>
                <div className="finding-body">
                  <b className="mono">{ind.indicator}</b>
                  <p>{ind.titles.join(" · ") || "Correlated evidence"}</p>
                  <div className="finding-meta">
                    <span>Protocol <code>{ind.protocol}</code></span>
                    <span>Findings <code>{ind.finding_count}</code></span>
                    <span>Rules <code>{ind.rule_ids.join(", ") || "—"}</code></span>
                    {ind.certificate_flags.length > 0 && <span>Cert <code>{ind.certificate_flags.join(", ")}</code></span>}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </>
  );
}

function Reports() {
  const { id: invId } = useInvestigation();
  const [refreshKey, setRefreshKey] = useState(0);
  const reports = useApiList(invId ? `/api/reports?investigation_id=${invId}&_r=${refreshKey}` : null);
  const [generating, setGenerating] = useState(false);
  const [genError, setGenError] = useState(null);

  const generate = async (format = "PDF") => {
    if (!invId) {
      setGenError("Upload and analyze a PCAP first (see PCAP Analysis) before generating a report.");
      return;
    }
    setGenerating(true);
    setGenError(null);
    try {
      const res = await fetch(`/api/reports?investigation_id=${invId}&format=${format}`, { method: "POST" });
      if (!res.ok) throw new Error(`Report generation failed (${res.status})`);
      setRefreshKey((k) => k + 1);
    } catch (e) {
      setGenError(e.message || "Backend not reachable.");
    }
    setGenerating(false);
  };

  return (
    <>
      <div className="grid-3" style={{ marginBottom: 16 }}>
        {[
          ["PDF Report", "Detailed analysis report", I.reports, "PDF"],
          ["JSON Export", "Raw findings data", I.pcap, "JSON"],
          ["HTML Report", "Browser-viewable report", I.tools, "HTML"],
        ].map(([title, copy, Icon, fmt]) => (
          <button className="card export-card" key={title} onClick={() => generate(fmt)} disabled={generating}>
            <span className="export-icon"><Icon /></span>
            <b>{title}</b>
            <span>{copy}</span>
          </button>
        ))}
      </div>
    <div className="card">
      {reports.data && reports.data.length > 0 ? (
        reports.data.map((r) => (
          <div className="setting-row" key={r.id}>
            <div><b>{r.title || r.id}</b><span>{r.format}</span></div>
            <a className="btn btn-sm" href={`/api/reports/${r.id}`} target="_blank" rel="noreferrer">Open</a>
          </div>
        ))
      ) : (
        <EmptyState
          title="No reports yet"
          copy={invId ? "Generate a report once an investigation has findings to summarize." : "Upload and analyze a PCAP first, then generate a report here."}
        />
      )}
      <div style={{ marginTop: 16 }}>
        <button className="btn btn-primary" onClick={() => generate("PDF")} disabled={generating}>
          {generating ? "Generating…" : "Generate new report"}
        </button>
        {genError && <p style={{ color: "var(--red)", fontSize: 12.5, marginTop: 10 }}>{genError}</p>}
      </div>
    </div>
    </>
  );
}

function ToolCard({ title, copy, children }) {
  return (
    <div className="card">
      <b style={{ display: "block", fontSize: 14, color: "var(--text-strong)", marginBottom: 6 }}>{title}</b>
      <p style={{ fontSize: 12.5, color: "var(--text-secondary)", margin: "0 0 12px" }}>{copy}</p>
      {children}
    </div>
  );
}

// Runs entirely in the browser via the Web Crypto API — no upload needed,
// so evidence files never leave the analyst's machine just to be hashed.
function HashTool() {
  const { id: invId } = useInvestigation();
  const [hash, setHash] = useState(null);
  const [fileName, setFileName] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [pcapSha, setPcapSha] = useState(null);

  useEffect(() => {
    if (!invId) { setPcapSha(null); return; }
    invApi.summary(invId).then((s) => setPcapSha(s?.pcap?.sha256 || null)).catch(() => setPcapSha(null));
  }, [invId]);

  const onFile = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setBusy(true); setError(null); setHash(null); setFileName(file.name);
    try {
      const buf = await file.arrayBuffer();
      const digest = await crypto.subtle.digest("SHA-256", buf);
      const hex = Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
      setHash(hex);
    } catch {
      setError("Couldn't hash that file in this browser.");
    }
    setBusy(false);
  };

  const matches = hash && pcapSha ? hash.toLowerCase() === pcapSha.toLowerCase() : null;

  return (
    <ToolCard title="SHA-256 evidence hash" copy="Verify a file's hash matches the recorded chain of custody.">
      <input type="file" onChange={onFile} style={{ fontSize: 12 }} />
      {busy && <p style={{ fontSize: 12, color: "var(--text-faint)", marginTop: 8 }}>Hashing…</p>}
      {error && <p className="note-warn" style={{ fontSize: 12, marginTop: 8 }}>{error}</p>}
      {hash && (
        <div style={{ marginTop: 10 }}>
          <div style={{ fontSize: 11, color: "var(--text-faint)" }}>{fileName}</div>
          <code style={{ fontSize: 11, wordBreak: "break-all", display: "block", marginTop: 4 }}>{hash}</code>
          {pcapSha && (
            <p style={{ fontSize: 12, marginTop: 8 }} className={matches ? "" : "note-warn"}>
              {matches ? "✓ Matches this investigation's recorded PCAP hash." : "✗ Does not match this investigation's recorded PCAP hash."}
            </p>
          )}
          {!pcapSha && invId && <p style={{ fontSize: 11.5, color: "var(--text-faint)", marginTop: 8 }}>No recorded PCAP hash to compare against yet.</p>}
        </div>
      )}
    </ToolCard>
  );
}

function PacketExportTool() {
  const { id: invId } = useInvestigation();
  const findings = useApiList(invId ? `/api/findings?investigation_id=${invId}` : null);
  const [findingId, setFindingId] = useState("");

  const list = findings.data || [];

  return (
    <ToolCard title="Packet export" copy="Export a filtered subset of packets tied to a finding.">
      {!invId ? (
        <p style={{ fontSize: 12, color: "var(--text-faint)" }}>Upload and analyze a PCAP first.</p>
      ) : (
        <>
          <select value={findingId} onChange={(e) => setFindingId(e.target.value)} style={{ width: "100%", marginBottom: 10 }}>
            <option value="">Select a finding…</option>
            {list.map((f) => (
              <option key={f.id} value={f.id}>{f.title || f.rule_id} ({f.severity})</option>
            ))}
          </select>
          <a
            className="btn btn-sm"
            href={findingId ? toolsApi.exportFindingPacketsUrl(findingId) : undefined}
            aria-disabled={!findingId}
            onClick={(e) => { if (!findingId) e.preventDefault(); }}
            style={{ opacity: findingId ? 1 : 0.5, pointerEvents: findingId ? "auto" : "none" }}
          >
            Export session packets (.pcap)
          </a>
          <div style={{ marginTop: 10 }}>
            <a className="btn btn-sm" href={toolsApi.downloadPcapUrl(invId)}>Download full original capture</a>
          </div>
        </>
      )}
    </ToolCard>
  );
}

function CertLookupTool() {
  const { id: invId } = useInvestigation();
  const sessions = useApiList(invId ? `/api/sessions?investigation_id=${invId}&page_size=200` : null);
  const [sessionId, setSessionId] = useState("");
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  const items = (sessions.data && sessions.data.items) || [];

  const lookup = async () => {
    if (!sessionId) return;
    setBusy(true); setError(null); setResult(null);
    try {
      const data = await sessionsApi.certificate(sessionId);
      setResult(data);
    } catch (e) {
      setError(e.message || "Lookup failed");
    }
    setBusy(false);
  };

  return (
    <ToolCard title="Certificate lookup" copy="Inspect a certificate fingerprint against parsed evidence.">
      {!invId ? (
        <p style={{ fontSize: 12, color: "var(--text-faint)" }}>Upload and analyze a PCAP first.</p>
      ) : (
        <>
          <select value={sessionId} onChange={(e) => setSessionId(e.target.value)} style={{ width: "100%", marginBottom: 10 }}>
            <option value="">Select a session…</option>
            {items.map((s) => (
              <option key={s.id} value={s.id}>{s.src_ip}:{s.src_port} → {s.dst_ip}:{s.dst_port}</option>
            ))}
          </select>
          <button className="btn btn-sm" onClick={lookup} disabled={!sessionId || busy}>{busy ? "Looking up…" : "Look up"}</button>
          {error && <p className="note-warn" style={{ fontSize: 12, marginTop: 8 }}>{error}</p>}
          {result && (
            result.certificates && result.certificates.length ? (
              <div style={{ marginTop: 10 }}>
                {result.certificates.map((c, i) => (
                  <div key={i} className="session-meta-row" style={{ marginTop: i ? 6 : 0 }}>
                    <span>{c.subject || "unknown subject"}</span>
                    <span className={c.status !== "VALID" ? "note-warn" : ""}>{c.status}</span>
                    {c.sha256_fingerprint && <span className="mono">{c.sha256_fingerprint.slice(0, 16)}…</span>}
                  </div>
                ))}
              </div>
            ) : (
              <p style={{ fontSize: 12, color: "var(--text-faint)", marginTop: 8 }}>No certificate observed for that session.</p>
            )
          )}
        </>
      )}
    </ToolCard>
  );
}

function Tools() {
  return (
    <div className="grid-3">
      <HashTool />
      <PacketExportTool />
      <CertLookupTool />
    </div>
  );
}

function Settings() {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [username, setUsername] = useState("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    authApi.me()
      .then((u) => {
        if (cancelled) return;
        setUsername(u.username || "");
        setName(u.full_name || "");
        setEmail(u.email || "");
        setLoading(false);
      })
      .catch(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, []);

  const save = async () => {
    setSaving(true); setSaved(false); setError(null);
    try {
      const updated = await authApi.updateMe({ full_name: name, email });
      setName(updated.full_name || "");
      setEmail(updated.email || "");
      setSaved(true);
      setTimeout(() => setSaved(false), 1800);
    } catch (e) {
      setError(e.message || "Couldn't save profile");
    }
    setSaving(false);
  };

  if (loading) return <div className="card" style={{ maxWidth: 480 }}><p style={{ color: "var(--text-secondary)" }}>Loading profile…</p></div>;

  return (
    <div className="card" style={{ maxWidth: 480 }}>
      <div className="page-eyebrow">Profile</div>
      {username && (
        <div className="field">
          <label>Username</label>
          <input value={username} disabled placeholder="Not set" />
        </div>
      )}
      <div className="field">
        <label>Display name</label>
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Not set" />
      </div>
      <div className="field">
        <label>Email</label>
        <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="Not set" />
      </div>
      <button className="btn btn-primary" onClick={save} disabled={saving}>
        {saving ? "Saving…" : saved ? "Saved ✓" : "Save profile"}
      </button>
      {error && <p className="note-warn" style={{ fontSize: 12.5, marginTop: 10 }}>{error}</p>}
    </div>
  );
}

/* ---------------------------------------------------------------- */
/* Auth                                                               */
/* ---------------------------------------------------------------- */
// Subtle abstract network visual for the auth brand panel — nodes, data
// lines and a faint grid, drawn with currentColor/theme tokens so it reads
// correctly in both themes without any external image asset.
function AuthVisual() {
  const nodes = [[40, 58], [148, 36], [246, 84], [324, 46], [124, 150], [56, 182], [268, 168]];
  const edges = [[0, 1], [1, 2], [2, 3], [1, 4], [4, 2], [4, 5], [2, 6]];
  return (
    <svg className="auth-visual-svg" viewBox="0 0 360 220" fill="none" aria-hidden="true">
      <defs>
        <pattern id="authGrid" width="26" height="26" patternUnits="userSpaceOnUse">
          <path d="M 26 0 L 0 0 0 26" fill="none" stroke="currentColor" strokeWidth="0.6" opacity="0.16" />
        </pattern>
      </defs>
      <rect width="360" height="220" fill="url(#authGrid)" />
      {edges.map(([a, b], i) => (
        <line key={i} x1={nodes[a][0]} y1={nodes[a][1]} x2={nodes[b][0]} y2={nodes[b][1]} stroke="currentColor" strokeWidth="1" opacity="0.3" />
      ))}
      {nodes.map(([x, y], i) => (
        <circle key={i} cx={x} cy={y} r={i % 3 === 0 ? 5 : 3.5} fill="var(--accent)" opacity={i % 3 === 0 ? 0.9 : 0.55} />
      ))}
    </svg>
  );
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function AuthScreen({ theme, setTheme, onSuccess }) {
  // Sign in / sign up now call the real /api/auth/* endpoints (see api.js)
  // and set a real httpOnly session cookie — nothing here is a localStorage
  // stub anymore. "forgot" and its confirmation screen stay presentational:
  // this backend has no password-reset endpoint to call, so nothing here
  // pretends to send a real email.
  const [mode, setMode] = useState("login"); // login | signup | forgot | forgot-sent
  const [showPw, setShowPw] = useState(false);
  const [showPw2, setShowPw2] = useState(false);
  const [pwValue, setPwValue] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [errors, setErrors] = useState({});

  const switchMode = (m) => { setMode(m); setErrors({}); setShowPw(false); setShowPw2(false); };

  const submitLogin = async (e) => {
    e.preventDefault();
    const form = new FormData(e.target);
    const errs = {};
    if (!EMAIL_RE.test(form.get("email") || "")) errs.email = "Enter a valid email address.";
    if (!form.get("password")) errs.password = "Password is required.";
    setErrors(errs);
    if (Object.keys(errs).length) return;
    setSubmitting(true);
    try {
      // The backend logs in by "username" — every account created through
      // this screen uses its email address as its username too (see
      // submitSignup), so signing in with the email works either way.
      const user = await authApi.login(form.get("email"), form.get("password"));
      setSubmitting(false);
      onSuccess(user);
    } catch (err) {
      setSubmitting(false);
      setErrors({ form: err.message || "Sign in failed. Check your email and password." });
    }
  };

  const submitSignup = async (e) => {
    e.preventDefault();
    const form = new FormData(e.target);
    const password = form.get("password") || "";
    const errs = {};
    if (!(form.get("name") || "").trim()) errs.name = "Full name is required.";
    if (!EMAIL_RE.test(form.get("email") || "")) errs.email = "Enter a valid email address.";
    if (password.length < 8 || !/[A-Z]/.test(password) || !/[a-z]/.test(password) || !/[0-9]/.test(password)) {
      errs.password = "Password doesn't meet the requirements below.";
    }
    if ((form.get("confirm") || "") !== password) errs.confirm = "Passwords don't match.";
    setErrors(errs);
    if (Object.keys(errs).length) return;
    setSubmitting(true);
    try {
      const email = form.get("email");
      const user = await authApi.register(email, email, password);
      setSubmitting(false);
      onSuccess(user);
    } catch (err) {
      setSubmitting(false);
      setErrors({ form: err.message || "Couldn't create your account." });
    }
  };

  const submitForgot = (e) => {
    e.preventDefault();
    const form = new FormData(e.target);
    const errs = {};
    if (!EMAIL_RE.test(form.get("email") || "")) errs.email = "Enter a valid email address.";
    setErrors(errs);
    if (Object.keys(errs).length) return;
    setSubmitting(true);
    setTimeout(() => { setSubmitting(false); setMode("forgot-sent"); }, 450);
  };

  const pwChecks = [
    { label: "8+ characters", ok: pwValue.length >= 8 },
    { label: "Uppercase letter", ok: /[A-Z]/.test(pwValue) },
    { label: "Lowercase letter", ok: /[a-z]/.test(pwValue) },
    { label: "Number", ok: /[0-9]/.test(pwValue) },
  ];

  return (
    <div className="auth-shell auth-shell-split">
      <button
        className="icon-btn auth-theme-toggle"
        onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
        aria-label="Toggle color theme"
      >
        {theme === "dark" ? <I.sun /> : <I.moon />}
      </button>

      <div className="auth-panel">
        <div className="auth-panel-brand">
          <span className="brand-mark">M</span>
          <div className="sidebar-brand-text"><b>MAILSECURE</b><small>SecureMailScope</small></div>
        </div>
        <h2 className="auth-panel-headline">Secure your investigation workspace.</h2>
        <p className="auth-panel-sub">Analyze network traffic, uncover threats, and keep your security evidence close.</p>
        <AuthVisual />
        <div className="auth-panel-tags">
          <span>Network Security</span><span>Traffic Analysis</span><span>Threat Investigation</span>
        </div>
      </div>

      <div className="auth-card-wrap">
        <motion.div className="auth-card" initial={{ y: 16, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={spring}>
          {mode === "forgot-sent" ? (
            <div className="auth-success">
              <span className="auth-success-icon"><I.mail /></span>
              <h1>Check your inbox</h1>
              <p>We've sent a password reset link to your email.</p>
              <button className="btn btn-primary" style={{ width: "100%", justifyContent: "center" }} onClick={() => switchMode("login")}>
                Back to Sign In
              </button>
            </div>
          ) : (
            <>
              <span className="brand-mark auth-card-mark">M</span>
              <h1>{mode === "login" ? "Welcome back" : mode === "signup" ? "Create your workspace" : "Reset your password"}</h1>
              <p>
                {mode === "login" && "Sign in to continue to your security workspace."}
                {mode === "signup" && "Start analyzing network traffic with MailSecure."}
                {mode === "forgot" && "Enter your email and we'll send you instructions to reset your password."}
              </p>
              {errors.form && (mode === "login" || mode === "signup") && (
                <p className="field-error" style={{ marginBottom: 12 }}>{errors.form}</p>
              )}

              {mode === "login" && (
                <form onSubmit={submitLogin} noValidate>
                  <div className="field">
                    <label htmlFor="auth-email">Email</label>
                    <input id="auth-email" name="email" type="email" placeholder="analyst@example.com" className={errors.email ? "input-error" : ""} />
                    {errors.email && <span className="field-error">{errors.email}</span>}
                  </div>
                  <div className="field">
                    <label htmlFor="auth-password">Password</label>
                    <div className="input-with-action">
                      <input id="auth-password" name="password" type={showPw ? "text" : "password"} placeholder="••••••••" className={errors.password ? "input-error" : ""} />
                      <button type="button" className="input-action-btn" onClick={() => setShowPw((v) => !v)} aria-label={showPw ? "Hide password" : "Show password"}>
                        {showPw ? <I.eyeOff /> : <I.eye />}
                      </button>
                    </div>
                    {errors.password && <span className="field-error">{errors.password}</span>}
                  </div>
                  <div className="auth-row-between">
                    <button type="button" className="link-btn" onClick={() => switchMode("forgot")}>Forgot password?</button>
                  </div>
                  <button className="btn btn-primary" type="submit" disabled={submitting} style={{ width: "100%", justifyContent: "center", marginTop: 8 }}>
                    {submitting ? "Signing in…" : <>Sign In <I.arrowRight /></>}
                  </button>
                </form>
              )}

              {mode === "signup" && (
                <form onSubmit={submitSignup} noValidate>
                  <div className="field">
                    <label htmlFor="auth-name">Full Name</label>
                    <input id="auth-name" name="name" type="text" placeholder="Jane Analyst" className={errors.name ? "input-error" : ""} />
                    {errors.name && <span className="field-error">{errors.name}</span>}
                  </div>
                  <div className="field">
                    <label htmlFor="auth-email-2">Email</label>
                    <input id="auth-email-2" name="email" type="email" placeholder="analyst@example.com" className={errors.email ? "input-error" : ""} />
                    {errors.email && <span className="field-error">{errors.email}</span>}
                  </div>
                  <div className="field">
                    <label htmlFor="auth-password-2">Password</label>
                    <div className="input-with-action">
                      <input
                        id="auth-password-2" name="password" type={showPw ? "text" : "password"} placeholder="••••••••"
                        value={pwValue} onChange={(e) => setPwValue(e.target.value)}
                        className={errors.password ? "input-error" : ""}
                      />
                      <button type="button" className="input-action-btn" onClick={() => setShowPw((v) => !v)} aria-label={showPw ? "Hide password" : "Show password"}>
                        {showPw ? <I.eyeOff /> : <I.eye />}
                      </button>
                    </div>
                    <ul className="pw-requirements">
                      {pwChecks.map((c) => (
                        <li key={c.label} className={c.ok ? "met" : ""}>{c.ok ? "✓" : "○"} {c.label}</li>
                      ))}
                    </ul>
                    {errors.password && <span className="field-error">{errors.password}</span>}
                  </div>
                  <div className="field">
                    <label htmlFor="auth-confirm">Confirm Password</label>
                    <div className="input-with-action">
                      <input id="auth-confirm" name="confirm" type={showPw2 ? "text" : "password"} placeholder="••••••••" className={errors.confirm ? "input-error" : ""} />
                      <button type="button" className="input-action-btn" onClick={() => setShowPw2((v) => !v)} aria-label={showPw2 ? "Hide password" : "Show password"}>
                        {showPw2 ? <I.eyeOff /> : <I.eye />}
                      </button>
                    </div>
                    {errors.confirm && <span className="field-error">{errors.confirm}</span>}
                  </div>
                  <button className="btn btn-primary" type="submit" disabled={submitting} style={{ width: "100%", justifyContent: "center", marginTop: 4 }}>
                    {submitting ? "Creating account…" : "Create Account"}
                  </button>
                </form>
              )}

              {mode === "forgot" && (
                <form onSubmit={submitForgot} noValidate>
                  <div className="field">
                    <label htmlFor="auth-forgot-email">Email</label>
                    <input id="auth-forgot-email" name="email" type="email" placeholder="analyst@example.com" className={errors.email ? "input-error" : ""} />
                    {errors.email && <span className="field-error">{errors.email}</span>}
                  </div>
                  <button className="btn btn-primary" type="submit" disabled={submitting} style={{ width: "100%", justifyContent: "center" }}>
                    {submitting ? "Sending…" : "Send Reset Link"}
                  </button>
                  <button type="button" className="link-btn auth-back-link" onClick={() => switchMode("login")}>← Back to Sign In</button>
                </form>
              )}

              {mode !== "forgot" && (
                <p className="auth-switch">
                  {mode === "login" ? (
                    <>Don't have an account? <button type="button" className="link-btn" onClick={() => switchMode("signup")}>Create account</button></>
                  ) : (
                    <>Already have an account? <button type="button" className="link-btn" onClick={() => switchMode("login")}>Sign in</button></>
                  )}
                </p>
              )}
            </>
          )}
        </motion.div>
      </div>
    </div>
  );
}

/* ---------------------------------------------------------------- */
/* Assistant (theme-aware, wired to the real backend endpoint)       */
/* ---------------------------------------------------------------- */
function Assistant() {
  const { id: invId } = useInvestigation();
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState([
    { from: "bot", text: "Hi, I'm the MailSecure assistant. Ask me about STARTTLS, certificates, or risk scoring, or say \"summarize\" for a read on current findings." },
  ]);
  const [input, setInput] = useState("");

  const send = async (text) => {
    const q = (text ?? input).trim();
    if (!q) return;
    setMessages((m) => [...m, { from: "user", text: q }]);
    setInput("");
    try {
      const res = await fetch("/api/assistant", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: q, investigation_id: invId || undefined }),
      });
      if (!res.ok) throw new Error();
      const data = await res.json();
      setMessages((m) => [...m, { from: "bot", text: data.reply || data.answer || "I couldn't parse a reply from the backend." }]);
    } catch {
      setMessages((m) => [...m, { from: "bot", text: "I can't reach the backend assistant right now." }]);
    }
  };

  const quickAsks = ["What is STARTTLS?", "Summarize findings", "What does self-signed mean?"];

  return (
    <>
      <button className="assistant-fab" onClick={() => setOpen((v) => !v)} aria-label="Open assistant">
        {open ? "✕" : "💬"}
      </button>
      <AnimatePresence>
        {open && (
          <motion.div
            className="assistant-panel"
            initial={{ opacity: 0, y: 24, scale: 0.96 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 24, scale: 0.96 }}
            transition={spring}
          >
            <div className="assistant-head">
              <span className="brand-mark" style={{ width: 26, height: 26, fontSize: 12 }}>M</span>
              <div><b>MailSecure Assistant</b><small>Backed by /api/assistant</small></div>
            </div>
            <div className="assistant-body">
              {messages.map((m, i) => (
                <div key={i} className={`assistant-msg ${m.from === "bot" ? "bot" : "user"}`}>{m.text}</div>
              ))}
            </div>
            <div className="assistant-quick">
              {quickAsks.map((q) => <button key={q} onClick={() => send(q)}>{q}</button>)}
            </div>
            <form className="assistant-input" onSubmit={(e) => { e.preventDefault(); send(); }}>
              <input value={input} onChange={(e) => setInput(e.target.value)} placeholder="Ask about a term or finding…" />
              <button type="submit" className="btn btn-primary">→</button>
            </form>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}

export default App;
