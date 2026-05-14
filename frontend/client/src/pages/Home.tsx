/*
Design philosophy: Swiss Cybernetic Control Room.
*/
import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  CheckCircle2,
  Copy,
  KeyRound,
  LogOut,
  Network,
  Plus,
  RadioTower,
  RefreshCw,
  Search,
  ShieldAlert,
  TerminalSquare,
  UserRound,
} from "lucide-react";
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell,
  Line, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import { toast } from "sonner";

const HERO_IMAGE = "";
const GRID_IMAGE = "";
const ORBIT_IMAGE = "";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "";

type Overview = {
  total_incidents: number;
  new_incidents: number;
  active_agents: number;
  total_logs_processed: number;
  avg_ml_score: number;
};

type TimeseriesPoint = {
  timestamp: string;
  incident_count: number;
  log_volume: number;
  avg_severity: number;
};

type StatsResponse = {
  overview: Overview;
  timeseries: TimeseriesPoint[];
  threat_distribution: Record<string, number>;
  top_sources: Array<{ ip: string; incident_count: number; threat_types: string[] }>;
};

type Incident = {
  id: string;
  agent_id: string;
  agent_name?: string;
  created_at: string;
  threat_type: string;
  severity: number;
  status: string;
  ml_score: number;
  summary?: Record<string, number>;
  details?: Record<string, unknown>;
  raw_logs_sample?: unknown[];
  timeline?: Array<Record<string, unknown>>;
};

type Agent = {
  id: string;
  name: string;
  token_prefix?: string;
  last_seen?: string;
  status: string;
  logs_sent_today?: number;
  last_incident_at?: string;
};

const demoStats: StatsResponse = {
  overview: {
    total_incidents: 45,
    new_incidents: 12,
    active_agents: 8,
    total_logs_processed: 2500000,
    avg_ml_score: 0.34,
  },
  timeseries: [
    { timestamp: "2026-05-11T00:00:00Z", incident_count: 3, log_volume: 45000, avg_severity: 2.5 },
    { timestamp: "2026-05-11T03:00:00Z", incident_count: 5, log_volume: 76000, avg_severity: 3.1 },
    { timestamp: "2026-05-11T06:00:00Z", incident_count: 2, log_volume: 41000, avg_severity: 2.2 },
    { timestamp: "2026-05-11T09:00:00Z", incident_count: 8, log_volume: 98000, avg_severity: 4.0 },
    { timestamp: "2026-05-11T12:00:00Z", incident_count: 7, log_volume: 115000, avg_severity: 3.7 },
    { timestamp: "2026-05-11T15:00:00Z", incident_count: 12, log_volume: 151000, avg_severity: 4.4 },
  ],
  threat_distribution: { ddos: 5, port_scan: 28, anomaly: 10, other: 2 },
  top_sources: [
    { ip: "192.168.1.100", incident_count: 8, threat_types: ["port_scan"] },
    { ip: "10.10.4.17", incident_count: 5, threat_types: ["ddos", "anomaly"] },
    { ip: "172.16.8.44", incident_count: 4, threat_types: ["anomaly"] },
  ],
};

const demoIncidents: Incident[] = [
  {
    id: "f2b74f24-7e51-43b2-9b37-0d3d99f741aa",
    agent_id: "agent-1",
    agent_name: "router-office-1",
    created_at: "2026-05-11T12:05:00Z",
    threat_type: "port_scan",
    severity: 4,
    status: "new",
    ml_score: 0.72,
    summary: { unique_src_ips: 1, unique_dst_ports: 150, packet_count: 5000, time_window_sec: 300 },
    details: { top_dst_ports: [22, 80, 443, 3389, 8080], packets_per_second: 16.67, entropy_dst_ports: 0.92 },
    raw_logs_sample: [{ src_ip: "192.168.1.100", dst_port: 22, protocol: "TCP", tcp_flags: ["SYN"] }],
    timeline: [{ timestamp: "2026-05-11T12:05:00Z", event: "incident_created" }],
  },
  {
    id: "a9e11140-222a-4b4c-9858-2c2d3e274612",
    agent_id: "agent-2",
    agent_name: "edge-dmz-2",
    created_at: "2026-05-11T13:28:00Z",
    threat_type: "ddos",
    severity: 5,
    status: "investigating",
    ml_score: 0.91,
    summary: { unique_src_ips: 840, unique_dst_ports: 2, packet_count: 98000, time_window_sec: 300 },
    details: { packets_per_second: 326.7, entropy_dst_ports: 0.16 },
    timeline: [{ timestamp: "2026-05-11T13:28:00Z", event: "incident_created" }],
  },
  {
    id: "c6d69044-2f98-47af-a155-97b1a02e3640",
    agent_id: "agent-3",
    agent_name: "branch-gateway-3",
    created_at: "2026-05-11T14:12:00Z",
    threat_type: "anomaly",
    severity: 3,
    status: "new",
    ml_score: 0.64,
    summary: { unique_src_ips: 12, unique_dst_ports: 32, packet_count: 12000, time_window_sec: 300 },
    details: { packets_per_second: 40, entropy_dst_ports: 0.67 },
    timeline: [{ timestamp: "2026-05-11T14:12:00Z", event: "incident_created" }],
  },
];

const demoAgents: Agent[] = [
  { id: "agent-1", name: "router-office-1", token_prefix: "a8c921f0...", last_seen: "2026-05-11T14:55:00Z", status: "active", logs_sent_today: 144, last_incident_at: "2026-05-11T12:05:00Z" },
  { id: "agent-2", name: "edge-dmz-2", token_prefix: "f114e7aa...", last_seen: "2026-05-11T15:01:00Z", status: "active", logs_sent_today: 221, last_incident_at: "2026-05-11T13:28:00Z" },
  { id: "agent-3", name: "branch-gateway-3", token_prefix: "92bd0cc1...", last_seen: "2026-05-11T13:48:00Z", status: "active", logs_sent_today: 98, last_incident_at: "2026-05-11T14:12:00Z" },
];

function authHeaders(token: string) {
  return { Authorization: `Bearer ${token}` };
}

async function apiFetch<T>(path: string, token?: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(token ? authHeaders(token) : {}),
      ...(options.headers || {}),
    },
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload?.error?.message || payload?.message || `HTTP ${response.status}`);
  }
  return payload?.data ?? payload;
}

function formatNumber(value: number) {
  return new Intl.NumberFormat("ru-RU").format(value);
}

function formatDate(value?: string) {
  if (!value) return "—";
  return new Intl.DateTimeFormat("ru-RU", { dateStyle: "short", timeStyle: "short" }).format(new Date(value));
}

function severityClass(severity: number) {
  if (severity >= 5) return "text-red-200 bg-red-500/20 border-red-400/30";
  if (severity >= 4) return "text-orange-200 bg-orange-500/20 border-orange-400/30";
  if (severity >= 3) return "text-amber-200 bg-amber-500/20 border-amber-400/30";
  return "text-cyan-200 bg-cyan-500/15 border-cyan-400/25";
}

function statusClass(status: string) {
  if (status === "new") return "text-red-100 bg-red-500/20 border-red-400/30";
  if (status === "investigating") return "text-amber-100 bg-amber-500/20 border-amber-400/30";
  if (status === "resolved") return "text-emerald-100 bg-emerald-500/20 border-emerald-400/30";
  return "text-slate-200 bg-slate-500/20 border-slate-400/30";
}

function LoginScreen({ onLogin }: { onLogin: (token: string) => void }) {
  const [login, setLogin] = useState("admin");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setLoading(true);
    try {
      const data = await apiFetch<{ token: string }>("/api/auth/login", undefined, {
        method: "POST",
        body: JSON.stringify({ login, password }),
      });
      localStorage.setItem("nm_jwt", data.token);
      onLogin(data.token);
      toast.success("Авторизация выполнена");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Не удалось авторизоваться");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="login-shell" style={{ backgroundImage: `linear-gradient(90deg, rgba(5,10,18,.95), rgba(5,10,18,.76), rgba(5,10,18,.28)), url(${HERO_IMAGE})` }}>
      <section className="login-panel">
        <div className="brand-mark"><ShieldAlert size={22} /><span>Network Monitor</span></div>
        <p className="eyebrow">ADMINISTRATOR ACCESS</p>
        <h1>Операционный центр сетевых аномалий</h1>
        <p className="login-copy">Авторизуйтесь, чтобы открыть dashboard, графики, инциденты, список агентов и управление статусами реагирования.</p>
        <form onSubmit={submit} className="login-form">
          <label>Логин администратора<input value={login} onChange={(e) => setLogin(e.target.value)} autoComplete="username" required /></label>
          <label>Пароль<input value={password} onChange={(e) => setPassword(e.target.value)} type="password" autoComplete="current-password" required /></label>
          <button className="primary-action" disabled={loading}>{loading ? "Проверка доступа..." : "Войти в панель"}</button>
        </form>
        <div className="login-footnote"><TerminalSquare size={16} /> API endpoint: <code>{API_BASE_URL || "same-origin /api"}</code></div>
      </section>
    </main>
  );
}

function MetricCard({ icon, label, value, hint, tone = "cyan" }: { icon: React.ReactNode; label: string; value: string; hint: string; tone?: string }) {
  return <article className={`metric-card tone-${tone}`}>{icon}<div><span>{label}</span><strong>{value}</strong><small>{hint}</small></div></article>;
}

const PERIOD_LABELS: Record<string, string> = { "1h": "1 час", "6h": "6 часов", "24h": "24 часа", "7d": "7 дней", "30d": "30 дней" };

function Dashboard({ stats, period, setPeriod }: { stats: StatsResponse; period: string; setPeriod: (v: string) => void }) {
  const distribution = Object.entries(stats.threat_distribution || {}).map(([name, value]) => ({ name, value }));
  const colors = ["#22d3ee", "#f59e0b", "#ef4444", "#94a3b8"];
  return (
    <section className="dashboard-grid">
      <div className="section-head wide">
        <div><p className="eyebrow">LIVE TELEMETRY</p><h2>Dashboard — {PERIOD_LABELS[period] || period}</h2></div>
        <select value={period} onChange={(e) => setPeriod(e.target.value)}>
          <option value="1h">1h</option><option value="6h">6h</option><option value="24h">24h</option><option value="7d">7d</option><option value="30d">30d</option>
        </select>
      </div>
      <MetricCard icon={<ShieldAlert />} label="Всего инцидентов" value={formatNumber(stats.overview.total_incidents)} hint={`за ${PERIOD_LABELS[period] || period}`} tone="amber" />
      <MetricCard icon={<AlertTriangle />} label="Новые" value={formatNumber(stats.overview.new_incidents)} hint="требуют реакции" tone="red" />
      <MetricCard icon={<RadioTower />} label="Активные агенты" value={formatNumber(stats.overview.active_agents)} hint="последняя активность" />
      <MetricCard icon={<Activity />} label="Логов обработано" value={formatNumber(stats.overview.total_logs_processed)} hint={`avg ML ${stats.overview.avg_ml_score.toFixed(2)}`} />

      <article className="chart-card large">
        <h3>Инциденты и объём логов</h3>
        <ResponsiveContainer width="100%" height={310}>
          <AreaChart data={stats.timeseries || []}>
            <defs><linearGradient id="volume" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#22d3ee" stopOpacity={0.35} /><stop offset="95%" stopColor="#22d3ee" stopOpacity={0} /></linearGradient></defs>
            <CartesianGrid stroke="#1e3a4a" strokeDasharray="3 3" />
            <XAxis dataKey="timestamp" tickFormatter={(v: string) => new Date(v).getHours() + ":00"} stroke="#7dd3fc" />
            <YAxis stroke="#64748b" />
            <Tooltip contentStyle={{ background: "#07111d", border: "1px solid #164e63", color: "#e2e8f0" }} labelFormatter={(v: string) => new Date(v).toLocaleString("ru-RU")} />
            <Area type="monotone" dataKey="log_volume" stroke="#22d3ee" fill="url(#volume)" name="Логи" />
            <Line type="monotone" dataKey="incident_count" stroke="#f59e0b" strokeWidth={2} name="Инциденты" />
          </AreaChart>
        </ResponsiveContainer>
      </article>

      <article className="chart-card">
        <h3>Типы угроз</h3>
        <ResponsiveContainer width="100%" height={260}>
          <PieChart>
            <Pie data={distribution} dataKey="value" nameKey="name" innerRadius={60} outerRadius={95} label={{ fill: '#e2e8f0', fontSize: 12 }}>
              {distribution.map((_, index) => <Cell key={index} fill={colors[index % colors.length]} />)}
            </Pie>
            <Tooltip contentStyle={{ background: "#07111d", border: "1px solid #164e63", color: "#e2e8f0" }} labelStyle={{ color: "#e2e8f0" }} />
          </PieChart>
        </ResponsiveContainer>
        <div className="legend-list">{distribution.map((item, index) => <span key={item.name}><i style={{ background: colors[index % colors.length] }} />{item.name}: {item.value}</span>)}</div>
      </article>

      <article className="chart-card">
        <h3>Средняя критичность</h3>
        <ResponsiveContainer width="100%" height={260}>
          <BarChart data={stats.timeseries}>
            <CartesianGrid stroke="#1e3a4a" strokeDasharray="3 3" />
            <XAxis dataKey="timestamp" tickFormatter={(v: string) => new Date(v).getHours() + ":00"} stroke="#7dd3fc" />
            <YAxis stroke="#64748b" />
            <Tooltip contentStyle={{ background: "#07111d", border: "1px solid #164e63", color: "#e2e8f0" }} />
            <Bar dataKey="avg_severity" fill="#f59e0b" radius={[4, 4, 0, 0]} name="Severity" />
          </BarChart>
        </ResponsiveContainer>
      </article>

      <article className="chart-card sources">
        <h3>Top источники</h3>
        {(stats.top_sources || []).map((source) => (
          <div className="source-row" key={source.ip}><code>{source.ip}</code><span>{source.incident_count} incident</span><small>{source.threat_types.join(", ")}</small></div>
        ))}
      </article>
    </section>
  );
}

function Incidents({ incidents, onOpen, onRefresh }: { incidents: Incident[]; onOpen: (i: Incident) => void; onRefresh: () => void }) {
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("all");
  const filtered = incidents.filter((item) => (status === "all" || item.status === status) && `${item.id} ${item.agent_name} ${item.threat_type}`.toLowerCase().includes(query.toLowerCase()));
  return (
    <section className="panel-block">
      <div className="section-head"><div><p className="eyebrow">INCIDENT QUEUE</p><h2>Инциденты</h2></div><button className="ghost-action" onClick={onRefresh}><RefreshCw size={16} /> Обновить</button></div>
      <div className="filters">
        <label><Search size={16} /><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Поиск по agent/threat/id" /></label>
        <select value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="all">Все статусы</option><option value="new">new</option><option value="investigating">investigating</option><option value="resolved">resolved</option><option value="false_positive">false_positive</option>
        </select>
      </div>
      <div className="incident-table">
        <div className="incident-row header"><span>Инцидент</span><span>Агент</span><span>Угроза</span><span>Severity</span><span>ML</span><span>Статус</span></div>
        {filtered.map((item) => (
          <button className="incident-row" key={item.id} onClick={() => onOpen(item)}>
            <code>{item.id.slice(0, 8)}</code><span>{item.agent_name || item.agent_id}</span><span>{item.threat_type}</span>
            <span className={`chip ${severityClass(item.severity)}`}>{item.severity}</span><span>{item.ml_score.toFixed(2)}</span>
            <span className={`chip ${statusClass(item.status)}`}>{item.status}</span>
          </button>
        ))}
      </div>
    </section>
  );
}

function Agents({ token, agents, onRefresh }: { token: string; agents: Agent[]; onRefresh: () => void }) {
  const [agentName, setAgentName] = useState("");
  const [createdToken, setCreatedToken] = useState("");
  const [loading, setLoading] = useState(false);
  async function createAgent(event: React.FormEvent) {
    event.preventDefault();
    setLoading(true);
    try {
      const data = await apiFetch<{ agent_id: string; agent_token: string; token?: string }>("/api/admin/agents/tokens", token, { method: "POST", body: JSON.stringify({ agent_name: agentName }) });
      setCreatedToken(data.agent_token || data.token || "");
      setAgentName("");
      toast.success("Токен агента создан. Скопируйте его сейчас — он показывается один раз.");
      onRefresh();
    } catch (error) { toast.error(error instanceof Error ? error.message : "Не удалось создать токен"); }
    finally { setLoading(false); }
  }
  return (
    <section className="panel-block">
      <div className="section-head"><div><p className="eyebrow">AGENT CONTROL</p><h2>Агенты и выпуск токенов</h2></div><button className="ghost-action" onClick={onRefresh}><RefreshCw size={16} /> Обновить</button></div>
      <form className="agent-form" onSubmit={createAgent}><input value={agentName} onChange={(e) => setAgentName(e.target.value)} placeholder="router-office-1" required /><button className="primary-action" disabled={loading}><Plus size={16} /> Создать токен</button></form>
      {createdToken && <div className="token-box"><KeyRound size={18} /><code>{createdToken}</code><button onClick={() => navigator.clipboard.writeText(createdToken).then(() => toast.success("Токен скопирован"))}><Copy size={15} /></button></div>}
      <div className="agent-grid">
        {agents.map((agent) => (
          <article className="agent-card" key={agent.id}>
            <div><Network /><strong>{agent.name}</strong></div>
            <span className={`chip ${agent.status === "active" ? "text-emerald-100 bg-emerald-500/20 border-emerald-400/30" : "text-slate-200 bg-slate-500/20 border-slate-400/30"}`}>{agent.status}</span>
            <p>token: <code>{agent.token_prefix || "—"}</code></p>
            <p>last seen: {formatDate(agent.last_seen)}</p>
            <p>logs today: {formatNumber(agent.logs_sent_today || 0)}</p>
            <p>last incident: {formatDate(agent.last_incident_at)}</p>
          </article>
        ))}
      </div>
    </section>
  );
}

function IncidentInspector({ incident, token, onClose, onUpdated }: { incident: Incident | null; token: string; onClose: () => void; onUpdated: () => void }) {
  const [status, setStatus] = useState("investigating");
  const [comment, setComment] = useState("");
  const [rawLogs, setRawLogs] = useState<any[] | null>(null);
  const [logsLoading, setLogsLoading] = useState(false);

  useEffect(() => {
    if (!incident || !token) return;
    setRawLogs(null);
    setLogsLoading(true);
    apiFetch<{ logs: any[]; total: number }>(`/api/agents/${incident.agent_id}/logs?limit=100`, token)
      .then((data) => setRawLogs(data.logs || []))
      .catch(() => setRawLogs([]))
      .finally(() => setLogsLoading(false));
  }, [incident?.id]);

  if (!incident) return null;
  const activeIncident = incident;

  async function updateStatus(event: React.FormEvent) {
    event.preventDefault();
    try {
      await apiFetch(`/api/incidents/${activeIncident.id}/status`, token, { method: "PUT", body: JSON.stringify({ status, comment }) });
      toast.success("Статус инцидента обновлен");
      onUpdated();
      onClose();
    } catch (error) { toast.error(error instanceof Error ? error.message : "Не удалось обновить статус"); }
  }

  return (
    <aside className="inspector">
      <div className="inspector-card">
        <button className="close" onClick={onClose}>×</button>
        <p className="eyebrow">INCIDENT DETAIL</p>
        <h2>{activeIncident.threat_type} <span className={`chip ${severityClass(activeIncident.severity)}`}>S{activeIncident.severity}</span></h2>
        <p className="muted"><code>{activeIncident.id}</code></p>
        <div className="detail-grid">
          <span>Агент</span><strong>{activeIncident.agent_name || activeIncident.agent_id}</strong>
          <span>Создан</span><strong>{formatDate(activeIncident.created_at)}</strong>
          <span>ML score</span><strong>{activeIncident.ml_score.toFixed(2)}</strong>
          <span>Статус</span><strong className={`chip ${statusClass(activeIncident.status)}`}>{activeIncident.status}</strong>
        </div>
        <h3>Summary</h3><pre>{JSON.stringify(activeIncident.summary || {}, null, 2)}</pre>
        <h3>Details</h3><pre>{JSON.stringify(activeIncident.details || {}, null, 2)}</pre>
        <h3>Сырые логи из ClickHouse</h3>
        {logsLoading ? <p className="muted">Загрузка...</p> : <pre>{JSON.stringify(rawLogs || [], null, 2)}</pre>}
        <form onSubmit={updateStatus} className="status-form">
          <select value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="new">new</option><option value="investigating">investigating</option><option value="resolved">resolved</option><option value="false_positive">false_positive</option>
          </select>
          <textarea value={comment} onChange={(e) => setComment(e.target.value)} placeholder="Комментарий расследования" />
          <button className="primary-action"><CheckCircle2 size={16} /> Обновить статус</button>
        </form>
      </div>
    </aside>
  );
}

export default function Home() {
  const [token, setToken] = useState(() => localStorage.getItem("nm_jwt") || "");
  const [section, setSection] = useState<"dashboard" | "incidents" | "agents">("dashboard");
  const [stats, setStats] = useState<StatsResponse>(demoStats);
  const [incidents, setIncidents] = useState<Incident[]>(demoIncidents);
  const [agents, setAgents] = useState<Agent[]>(demoAgents);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [period, setPeriod] = useState("24h");
  const [demoMode, setDemoMode] = useState(false);

  const criticalCount = useMemo(() => incidents.filter((i) => i.severity >= 4 && i.status !== "resolved").length, [incidents]);

  async function loadData() {
    if (!token) return;
    const maxRetries = 6;
    const retryDelayMs = 5000;
    let lastError: unknown = null;
    for (let attempt = 0; attempt < maxRetries; attempt++) {
      try {
        const [statsData, incidentsData, agentsData] = await Promise.all([
          apiFetch<StatsResponse>(`/api/stats?period=${period}`, token),
          apiFetch<{ items: Incident[] }>(`/api/incidents?page=1&limit=50&sort_by=created_at&order=desc&period=${period}`, token),
          apiFetch<{ items: Agent[] }>("/api/agents", token),
        ]);
        setStats(statsData);
        setIncidents(incidentsData.items || []);
        setAgents(agentsData.items || []);
        setDemoMode(false);
        return;
      } catch (error) {
        lastError = error;
        if (attempt === maxRetries - 2) toast.warning("Бэкенд ещё не готов, пробуем подключиться...");
        if (attempt < maxRetries - 1) await new Promise((resolve) => setTimeout(resolve, retryDelayMs));
      }
    }
    console.error("All retries exhausted, falling back to demo", lastError);
    setDemoMode(true);
    toast.warning("Бэкенд недоступен после 6 попыток. Показан демо-срез.");
  }

  useEffect(() => { void loadData(); }, [token, period]);

  function navTo(s: "dashboard" | "incidents" | "agents") {
    setSection(s);
    setSelectedIncident(null);
  }

  if (!token) return <LoginScreen onLogin={setToken} />;

  return (
    <main className="app-shell" style={{ backgroundImage: `linear-gradient(rgba(5,10,18,.92), rgba(5,10,18,.96)), url(${GRID_IMAGE})` }}>
      <nav className="side-rail">
        <div className="brand-mark"><ShieldAlert size={22} /><span>NM</span></div>
        <button className={section === "dashboard" ? "active" : ""} onClick={() => navTo("dashboard")}><BarChart3 /> Dashboard</button>
        <button className={section === "incidents" ? "active" : ""} onClick={() => navTo("incidents")}><ShieldAlert /> Инциденты</button>
        <button className={section === "agents" ? "active" : ""} onClick={() => navTo("agents")}><RadioTower /> Агенты</button>
        <button className="logout" onClick={() => { localStorage.removeItem("nm_jwt"); setToken(""); }}><LogOut /> Выход</button>
      </nav>
      <div className="workbench">
        <header className="topbar">
          <div><p className="eyebrow">NETWORK TRAFFIC MONITOR</p><h1>{section === "dashboard" ? "Command dashboard" : section === "incidents" ? "Incident response" : "Agent registry"}</h1></div>
          <div className="topbar-actions">
            {demoMode && <span className="chip text-amber-100 bg-amber-500/20 border-amber-400/30">demo fallback</span>}
            <span className="critical-chip"><AlertTriangle size={15} /> {criticalCount} critical/open</span>
            <span className="user-pill"><UserRound size={15} /> admin</span>
          </div>
        </header>
        {section === "dashboard" && <Dashboard stats={stats} period={period} setPeriod={setPeriod} />}
        {section === "incidents" && <Incidents incidents={incidents} onOpen={setSelectedIncident} onRefresh={loadData} />}
        {section === "agents" && <Agents token={token} agents={agents} onRefresh={loadData} />}
      </div>
      <IncidentInspector incident={selectedIncident} token={token} onClose={() => setSelectedIncident(null)} onUpdated={loadData} />
    </main>
  );
}