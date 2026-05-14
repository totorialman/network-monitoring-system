/*
Design philosophy: Swiss Cybernetic Control Room.
*/
import { useCallback, useEffect, useMemo, useState } from "react";
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

const GRID_IMAGE = "";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "";
const WS_BASE_URL = (() => {
  if (API_BASE_URL) return API_BASE_URL.replace(/^http/, "ws");
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${location.host}`;
})();

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
  overview: { total_incidents: 0, new_incidents: 0, active_agents: 0, total_logs_processed: 0, avg_ml_score: 0 },
  timeseries: [],
  threat_distribution: {},
  top_sources: [],
};

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

function statusLabel(status: string): string {
  const map: Record<string, string> = {
    new: "Новый", investigating: "Расследование", resolved: "Решён", false_positive: "Ложное срабатывание",
  };
  return map[status] || status;
}

function threatLabel(t: string): string {
  const map: Record<string, string> = {
    ddos: "DDoS", port_scan: "Сканирование портов", anomaly: "Аномалия", traffic: "Трафик",
  };
  return map[t] || t;
}

const PERIOD_LABELS: Record<string, string> = { "1h": "1 час", "6h": "6 часов", "24h": "24 часа", "7d": "7 дней", "30d": "30 дней" };

function LoginScreen({ onLogin }: { onLogin: (token: string) => void }) {
  const [login, setLogin] = useState("admin");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setLoading(true);
    try {
      const data = await apiFetch<{ token: string }>("/api/auth/login", undefined, { method: "POST", body: JSON.stringify({ login, password }) });
      localStorage.setItem("nm_jwt", data.token);
      onLogin(data.token);
      toast.success("Авторизация выполнена");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Не удалось авторизоваться");
    } finally { setLoading(false); }
  }

  return (
    <main className="login-shell">
      <section className="login-panel">
        <div className="brand-mark"><ShieldAlert size={22} /><span>Network Monitor</span></div>
        <p className="eyebrow">ДОСТУП АДМИНИСТРАТОРА</p>
        <h1>Центр мониторинга сетевых аномалий</h1>
        <p className="login-copy">Авторизуйтесь для доступа к панели управления, графикам, инцидентам, списку агентов и управлению реагированием.</p>
        <form onSubmit={submit} className="login-form">
          <label>Логин администратора<input value={login} onChange={(e) => setLogin(e.target.value)} autoComplete="username" required /></label>
          <label>Пароль<input value={password} onChange={(e) => setPassword(e.target.value)} type="password" autoComplete="current-password" required /></label>
          <button className="primary-action" disabled={loading}>{loading ? "Проверка доступа..." : "Войти в панель"}</button>
        </form>
        <div className="login-footnote"><TerminalSquare size={16} /> API: <code>{API_BASE_URL || "same-origin /api"}</code></div>
      </section>
    </main>
  );
}

function MetricCard({ icon, label, value, hint, tone = "cyan" }: { icon: React.ReactNode; label: string; value: string; hint: string; tone?: string }) {
  return <article className={`metric-card tone-${tone}`}>{icon}<div><span>{label}</span><strong>{value}</strong><small>{hint}</small></div></article>;
}

function Dashboard({ stats, period, setPeriod }: { stats: StatsResponse; period: string; setPeriod: (v: string) => void }) {
  const distribution = Object.entries(stats.threat_distribution || {}).map(([name, value]) => ({ name, value }));
  const colors = ["#22d3ee", "#f59e0b", "#ef4444", "#94a3b8"];

  const renderPieTooltip = useCallback((props: any) => {
    const { active, payload } = props;
    if (active && payload && payload.length) {
      return (
        <div style={{ background: "#07111d", border: "1px solid #164e63", color: "#e2e8f0", padding: "10px 14px", borderRadius: 10, fontSize: 13 }}>
          <p style={{ margin: 0, fontWeight: 600 }}>{payload[0].name}: {payload[0].value}</p>
        </div>
      );
    }
    return null;
  }, []);

  return (
    <section className="dashboard-grid">
      <div className="section-head wide">
        <div><p className="eyebrow">ТЕЛЕМЕТРИЯ</p><h2>Панель мониторинга — {PERIOD_LABELS[period] || period}</h2></div>
        <select value={period} onChange={(e) => setPeriod(e.target.value)}>
          <option value="1h">1 час</option><option value="6h">6 часов</option><option value="24h">24 часа</option><option value="7d">7 дней</option><option value="30d">30 дней</option>
        </select>
      </div>
      <MetricCard icon={<ShieldAlert />} label="Всего инцидентов" value={formatNumber(stats.overview.total_incidents)} hint={`за ${PERIOD_LABELS[period] || period}`} tone="amber" />
      <MetricCard icon={<AlertTriangle />} label="Новые" value={formatNumber(stats.overview.new_incidents)} hint="требуют реакции" tone="red" />
      <MetricCard icon={<RadioTower />} label="Активных агентов" value={formatNumber(stats.overview.active_agents)} hint="последняя активность" />
      <MetricCard icon={<Activity />} label="Логов обработано" value={formatNumber(stats.overview.total_logs_processed)} hint={`сред. ML ${stats.overview.avg_ml_score.toFixed(2)}`} />

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
            <Tooltip content={renderPieTooltip} />
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
            <Bar dataKey="avg_severity" fill="#f59e0b" radius={[4, 4, 0, 0]} name="Критичность" />
          </BarChart>
        </ResponsiveContainer>
      </article>

      <article className="chart-card sources">
        <h3>Основные источники</h3>
        {(stats.top_sources || []).map((source) => (
          <div className="source-row" key={source.ip}><code>{source.ip}</code><span>{source.incident_count} инцидентов</span><small>{source.threat_types.map(t => threatLabel(t)).join(", ")}</small></div>
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
      <div className="section-head"><div><p className="eyebrow">ОЧЕРЕДЬ ИНЦИДЕНТОВ</p><h2>Инциденты</h2></div><button className="ghost-action" onClick={onRefresh}><RefreshCw size={16} /> Обновить</button></div>
      <div className="filters">
        <label><Search size={16} /><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Поиск по агенту, угрозе, ID" /></label>
        <select value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="all">Все статусы</option><option value="new">Новый</option><option value="investigating">Расследование</option><option value="resolved">Решён</option><option value="false_positive">Ложное срабатывание</option>
        </select>
      </div>
      <div className="incident-table">
        <div className="incident-row header"><span>Инцидент</span><span>Агент</span><span>Угроза</span><span>Критичность</span><span>ML</span><span>Статус</span></div>
        {filtered.map((item) => (
          <button className="incident-row" key={item.id} onClick={() => onOpen(item)}>
            <code>{item.id.slice(0, 8)}</code><span>{item.agent_name || item.agent_id}</span><span>{threatLabel(item.threat_type)}</span>
            <span className={`chip ${severityClass(item.severity)}`}>{item.severity}</span><span>{item.ml_score.toFixed(2)}</span>
            <span className={`chip ${statusClass(item.status)}`}>{statusLabel(item.status)}</span>
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
      <div className="section-head"><div><p className="eyebrow">УПРАВЛЕНИЕ АГЕНТАМИ</p><h2>Агенты и выпуск токенов</h2></div><button className="ghost-action" onClick={onRefresh}><RefreshCw size={16} /> Обновить</button></div>
      <form className="agent-form" onSubmit={createAgent}><input value={agentName} onChange={(e) => setAgentName(e.target.value)} placeholder="router-office-1" required /><button className="primary-action" disabled={loading}><Plus size={16} /> Создать токен</button></form>
      {createdToken && <div className="token-box"><KeyRound size={18} /><code>{createdToken}</code><button onClick={() => navigator.clipboard.writeText(createdToken).then(() => toast.success("Токен скопирован"))}><Copy size={15} /></button></div>}
      <div className="agent-grid">
        {agents.map((agent) => (
          <article className="agent-card" key={agent.id}>
            <div><Network /><strong>{agent.name}</strong></div>
            <span className={`chip ${agent.status === "active" ? "text-emerald-100 bg-emerald-500/20 border-emerald-400/30" : "text-slate-200 bg-slate-500/20 border-slate-400/30"}`}>{agent.status === "active" ? "Активен" : "Неактивен"}</span>
            <p>токен: <code>{agent.token_prefix || "—"}</code></p>
            <p>последняя активность: {formatDate(agent.last_seen)}</p>
            <p>логов сегодня: {formatNumber(agent.logs_sent_today || 0)}</p>
            <p>последний инцидент: {formatDate(agent.last_incident_at)}</p>
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

  async function updateStatus(event: React.FormEvent) {
    event.preventDefault();
    try {
      await apiFetch(`/api/incidents/${incident!.id}/status`, token, { method: "PUT", body: JSON.stringify({ status, comment }) });
      toast.success("Статус инцидента обновлён");
      onUpdated();
      onClose();
    } catch (error) { toast.error(error instanceof Error ? error.message : "Не удалось обновить статус"); }
  }

  return (
    <aside className="inspector">
      <div className="inspector-card">
        <button className="close" onClick={onClose}>×</button>
        <p className="eyebrow">ДЕТАЛИ ИНЦИДЕНТА</p>
        <h2>{threatLabel(incident.threat_type)} <span className={`chip ${severityClass(incident.severity)}`}>S{incident.severity}</span></h2>
        <p className="muted"><code>{incident.id}</code></p>
        <div className="detail-grid">
          <span>Агент</span><strong>{incident.agent_name || incident.agent_id}</strong>
          <span>Создан</span><strong>{formatDate(incident.created_at)}</strong>
          <span>ML оценка</span><strong>{incident.ml_score.toFixed(2)}</strong>
          <span>Статус</span><strong className={`chip ${statusClass(incident.status)}`}>{statusLabel(incident.status)}</strong>
        </div>
        <h3>Сводка</h3><pre>{JSON.stringify(incident.summary || {}, null, 2)}</pre>
        <h3>Детали</h3><pre>{JSON.stringify(incident.details || {}, null, 2)}</pre>
        <h3>Сырые логи из ClickHouse</h3>
        {logsLoading ? <p className="muted">Загрузка...</p> : <pre>{JSON.stringify(rawLogs || [], null, 2)}</pre>}
        <form onSubmit={updateStatus} className="status-form">
          <select value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="new">Новый</option><option value="investigating">Расследование</option><option value="resolved">Решён</option><option value="false_positive">Ложное срабатывание</option>
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
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [period, setPeriod] = useState("24h");
  const [demoMode, setDemoMode] = useState(false);

  const criticalCount = useMemo(() => incidents.filter((i) => i.severity >= 4 && i.status !== "resolved").length, [incidents]);

  const loadData = useCallback(async () => {
    if (!token) return;
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
    } catch (error) {
      console.error("Failed to load data", error);
      setDemoMode(true);
    }
  }, [token, period]);

  // WebSocket — токен передаётся через query-параметр ?token=
  useEffect(() => {
    if (!token) return;
    let ws: WebSocket;
    let reconnectTimer: ReturnType<typeof setTimeout>;

    function connect() {
      const wsUrl = `${WS_BASE_URL}/api/ws?token=${encodeURIComponent(token)}`;
      ws = new WebSocket(wsUrl);
      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === "new_incident") {
            toast.info(`Новый инцидент: ${threatLabel(msg.payload?.threat_type || "")} (${msg.payload?.log_count || 0} логов)`);
            loadData();
          }
        } catch { /* ignore */ }
      };
      ws.onclose = () => {
        reconnectTimer = setTimeout(connect, 5000);
      };
      ws.onerror = () => {
        ws.close();
      };
    }

    connect();
    return () => {
      ws?.close();
      clearTimeout(reconnectTimer);
    };
  }, [token, loadData]);

  useEffect(() => { void loadData(); }, [token, period, loadData]);

  function navTo(s: "dashboard" | "incidents" | "agents") {
    setSection(s);
    setSelectedIncident(null);
  }

  if (!token) return <LoginScreen onLogin={setToken} />;

  return (
    <main className="app-shell" style={{ backgroundImage: `linear-gradient(rgba(5,10,18,.92), rgba(5,10,18,.96)), url(${GRID_IMAGE})` }}>
      <nav className="side-rail">
        <div className="brand-mark"><ShieldAlert size={22} /><span>NM</span></div>
        <button className={section === "dashboard" ? "active" : ""} onClick={() => navTo("dashboard")}><BarChart3 /> Панель</button>
        <button className={section === "incidents" ? "active" : ""} onClick={() => navTo("incidents")}><ShieldAlert /> Инциденты</button>
        <button className={section === "agents" ? "active" : ""} onClick={() => navTo("agents")}><RadioTower /> Агенты</button>
        <button className="logout" onClick={() => { localStorage.removeItem("nm_jwt"); setToken(""); }}><LogOut /> Выход</button>
      </nav>
      <div className="workbench">
        <header className="topbar">
          <div><p className="eyebrow">МОНИТОРИНГ СЕТЕВОГО ТРАФИКА</p><h1>{section === "dashboard" ? "Панель управления" : section === "incidents" ? "Реагирование на инциденты" : "Реестр агентов"}</h1></div>
          <div className="topbar-actions">
            {demoMode && <span className="chip text-amber-100 bg-amber-500/20 border-amber-400/30">демо-режим</span>}
            <span className="critical-chip"><AlertTriangle size={15} /> {criticalCount} критических/открытых</span>
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