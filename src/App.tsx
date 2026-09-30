import { useEffect, useState, type FormEvent, type ReactNode } from 'react'
import { Activity, AlertOctagon, ArrowUpRight, BadgeCheck, Bell, Check, ChevronDown, CircleHelp, Clock3, Command, Database, FileSearch, Filter, Fingerprint, LayoutDashboard, LogOut, MapPin, Menu, RefreshCw, Search, Shield, ShieldAlert, ShieldCheck, SlidersHorizontal, Sparkles, Users, X } from 'lucide-react'
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import './App.css'
import './investigation.css'

const API = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'
type Staff = { id: number; email: string; name: string; role: string }
type UserRecord = { id: number; user_id: string; name: string; email: string; scenario: string; home_location: string; transaction_count: number; flagged_count: number; last_transaction_date: string | null }
type AlertRecord = { fraud_flag_id: number; transaction_pk: number; transaction_id: string; user_id: string; user_name: string; amount: number; currency: string; transaction_date: string; location: string; risk_level: string; status: string; flag_status?: string; triggered_rules: string[]; device_id?: string; latitude?: number; longitude?: number }
type RuleResult = { rule_name: string; triggered: boolean; severity: string; evidence: Record<string, unknown>; evaluated_at: string }
type Investigation = { transaction: AlertRecord; rule_results: RuleResult[]; history: { transaction_id: string; transaction_date: string; location: string; latitude: number; longitude: number; amount: number }[]; notifications: { channel: string; status: string; recipient: string; created_at: string; error_message?: string | null }[] }
type Overview = { total_users: number; total_transactions: number; flagged_transactions: number; high_critical_risk: number; activity_graph_data: { day: string; count: number; amount: number }[] }
type DataRow = Record<string, unknown>

const scenarios = [
  { key: 'normal', label: 'Baseline behavior', color: 'mint', icon: <ShieldCheck size={17} /> },
  { key: 'high_amount', label: 'Unusual amounts', color: 'amber', icon: <ArrowUpRight size={17} /> },
  { key: 'high_velocity', label: 'Velocity burst', color: 'coral', icon: <Activity size={17} /> },
  { key: 'impossible_travel', label: 'Impossible travel', color: 'blue', icon: <MapPin size={17} /> },
  { key: 'multiple_signals', label: 'Multiple signals', color: 'rose', icon: <AlertOctagon size={17} /> },
]

function App() {
  const [token, setToken] = useState(() => sessionStorage.getItem('sentinel-token') || '')
  const [staff, setStaff] = useState<Staff | null>(null)
  const [email, setEmail] = useState('analyst@sentinel.local')
  const [password, setPassword] = useState('sentinel-demo')
  const [loginError, setLoginError] = useState('')
  const [page, setPage] = useState('Overview')
  const [overview, setOverview] = useState<Overview | null>(null)
  const [users, setUsers] = useState<UserRecord[]>([])
  const [alerts, setAlerts] = useState<AlertRecord[]>([])
  const [rules, setRules] = useState<DataRow[]>([])
  const [transactions, setTransactions] = useState<DataRow[]>([])
  const [activity, setActivity] = useState<DataRow[]>([])
  const [investigation, setInvestigation] = useState<Investigation | null>(null)
  const [search, setSearch] = useState('')
  const [riskFilter, setRiskFilter] = useState('ALL')
  const [comment, setComment] = useState('')
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState('')
  const [mobileOpen, setMobileOpen] = useState(false)

  async function request(path: string, options: RequestInit = {}) {
    const response = await fetch(`${API}${path}`, { ...options, headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}), ...options.headers } })
    if (response.status === 204) return null
    const data = await response.json()
    if (!response.ok) throw new Error(data.detail || 'The request could not be completed')
    return data
  }

  async function refresh(activeStaff: Staff | null = staff) {
    if (!token) return
    const [summary, userData, alertData, ruleData, transactionData] = await Promise.all([
      request('/dashboard/overview'), request('/users'), request('/fraud-alerts'), request('/rules'), request('/transactions?limit=100'),
    ])
    setOverview(summary)
    setUsers(userData.data)
    setAlerts(alertData.data)
    setRules(ruleData)
    setTransactions(transactionData.data)
    if (activeStaff?.role === 'admin') setActivity((await request('/activity')).data)
  }

  useEffect(() => {
    if (!token) return
    request('/auth/me').then((activeStaff: Staff) => { setStaff(activeStaff); return refresh(activeStaff) }).catch(() => { sessionStorage.removeItem('sentinel-token'); setToken('') })
  }, [token])
  useEffect(() => {
    if (!notice) return
    const timeout = window.setTimeout(() => setNotice(''), 3200)
    return () => window.clearTimeout(timeout)
  }, [notice])

  async function signIn(event: FormEvent) {
    event.preventDefault(); setBusy(true); setLoginError('')
    try {
      const result = await request('/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) })
      sessionStorage.setItem('sentinel-token', result.access_token); setStaff(result.user); setToken(result.access_token)
    } catch (error) { setLoginError(error instanceof Error ? error.message : 'Sign in failed') } finally { setBusy(false) }
  }
  async function generateDataset() {
    setBusy(true)
    try { const result = await request('/demo/generate', { method: 'POST' }); await refresh(); setNotice(`${result.generated_users} profiles and ${result.generated_transactions} transactions generated`); setPage('Users') }
    catch (error) { setNotice(error instanceof Error ? error.message : 'Generation failed') } finally { setBusy(false) }
  }
  async function analyze(userId: string) {
    setBusy(true)
    try { const result = await request(`/analysis/run/${userId}`, { method: 'POST' }); await refresh(); setNotice(`${userId}: ${result.flagged_transactions} flagged from ${result.transactions_analyzed} analyzed`) }
    catch (error) { setNotice(error instanceof Error ? error.message : 'Analysis failed') } finally { setBusy(false) }
  }
  async function analyzeAll() {
    setBusy(true)
    try { for (const user of users) await request(`/analysis/run/${user.user_id}`, { method: 'POST' }); await refresh(); setNotice('Analysis complete across all demo profiles') }
    catch (error) { setNotice(error instanceof Error ? error.message : 'Analysis failed') } finally { setBusy(false) }
  }
  async function openInvestigation(id: string) {
    try { setInvestigation(await request(`/transactions/${id}/analysis`)); setComment('') }
    catch (error) { setNotice(error instanceof Error ? error.message : 'Could not load investigation') }
  }
  async function submitReview(status: 'REVIEWED' | 'CLEARED') {
    if (!investigation) return
    try { await request(`/transactions/${investigation.transaction.transaction_id}/review`, { method: 'POST', body: JSON.stringify({ status, comment }) }); setInvestigation(null); await refresh(); setNotice(`Transaction ${status.toLowerCase()}`) }
    catch (error) { setNotice(error instanceof Error ? error.message : 'Review failed') }
  }
  async function toggleRule(rule: DataRow) {
    try { await request(`/rules/${encodeURIComponent(String(rule.name))}`, { method: 'PUT', body: JSON.stringify({ enabled: !rule.enabled }) }); await refresh(); setNotice(`${String(rule.name)} ${rule.enabled ? 'disabled' : 'enabled'}`) }
    catch (error) { setNotice(error instanceof Error ? error.message : 'Rule update failed') }
  }
  function signOut() {
    request('/auth/logout', { method: 'POST' }).catch(() => undefined); sessionStorage.removeItem('sentinel-token'); setToken(''); setStaff(null)
  }

  if (!token) return <main className="login-screen">
    <div className="login-visual"><div className="scanline" /><div className="login-brand"><span className="brand-mark"><Shield size={20} /></span><span>SENTINEL</span></div><div className="login-message"><span className="eyebrow">FINANCIAL CRIME INTELLIGENCE</span><h1>Signal in.<br /><i>Noise out.</i></h1><p>Investigate transaction behavior with transparent, deterministic evidence.</p></div><div className="login-coordinate">SECURE OPERATIONS <span>•</span> APAC REGION</div></div>
    <div className="login-form-wrap"><form className="login-form" onSubmit={signIn}><span className="eyebrow">ANALYST ACCESS</span><h2>Welcome back</h2><p className="muted">Sign in to your investigation workspace.</p><label>Email address<input type="email" value={email} onChange={(event) => setEmail(event.target.value)} autoComplete="username" required /></label><label>Password<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" required /></label>{loginError && <div className="form-error">{loginError}</div>}<button className="button primary full" disabled={busy}>{busy ? 'Signing in…' : 'Access workspace'}<ArrowUpRight size={16} /></button><div className="demo-credential"><Fingerprint size={16} /><span>DEMO ACCESS</span><code>analyst@sentinel.local</code><code>sentinel-demo</code></div></form></div>
  </main>

  const nav = [{ name: 'Overview', icon: LayoutDashboard }, { name: 'Fraud alerts', icon: ShieldAlert }, { name: 'Users', icon: Users }, { name: 'Transactions', icon: Activity }, { name: 'Rules', icon: SlidersHorizontal }, ...(staff?.role === 'admin' ? [{ name: 'Activity log', icon: BadgeCheck }] : [])]
  const shownAlerts = alerts.filter((item) => (riskFilter === 'ALL' || item.risk_level === riskFilter) && `${item.transaction_id} ${item.user_id} ${item.user_name}`.toLowerCase().includes(search.toLowerCase()))
  const shownUsers = users.filter((item) => `${item.user_id} ${item.name} ${item.email}`.toLowerCase().includes(search.toLowerCase()))
  const shownTransactions = transactions.filter((item) => `${item.transaction_id} ${item.user_id} ${item.location}`.toLowerCase().includes(search.toLowerCase()))

  return <div className="app-shell">
    <aside className={`sidebar ${mobileOpen ? 'mobile-open' : ''}`}>
      <div className="sidebar-brand"><span className="brand-mark"><Shield size={19} /></span><span>SENTINEL<small>FRAUD INTELLIGENCE</small></span><button className="icon-button sidebar-close" onClick={() => setMobileOpen(false)} aria-label="Close navigation"><X size={17} /></button></div>
      <div className="workspace-switch"><span className="workspace-icon"><Command size={15} /></span><span>Operations desk<small>Internal environment</small></span><ChevronDown size={14} /></div>
      <span className="nav-label">WORKSPACE</span><nav>{nav.map(({ name, icon: Icon }) => <button key={name} className={`nav-item ${page === name ? 'active' : ''}`} onClick={() => { setPage(name); setSearch(''); setMobileOpen(false) }}><Icon size={17} /><span>{name}</span>{name === 'Fraud alerts' && alerts.some((item) => item.status === 'UNREVIEWED') && <small>{alerts.filter((item) => item.status === 'UNREVIEWED').length}</small>}</button>)}</nav>
      <div className="sidebar-bottom"><div className="system-health"><span className="health-dot" /><span>All systems operational</span><span className="health-ping" /></div><div className="sidebar-user"><div className="avatar">{staff?.name.split(' ').map((part) => part[0]).join('')}</div><div><strong>{staff?.name}</strong><small>{staff?.role} · SENTINEL</small></div><button className="icon-button" title="Sign out" onClick={signOut}><LogOut size={16} /></button></div></div>
    </aside>
    {mobileOpen && <button className="mobile-scrim" aria-label="Close navigation" onClick={() => setMobileOpen(false)} />}
    <main className="main-area">
      <header className="topbar"><div className="crumb"><button className="icon-button mobile-menu" onClick={() => setMobileOpen(true)} aria-label="Open navigation"><Menu size={19} /></button><span>Workspace</span><span className="crumb-slash">/</span><strong>{page}</strong></div><div className="topbar-actions"><span className="date-stamp"><span className="live-dot" />LIVE MONITORING</span><button className="icon-button notification-button" title="Notifications"><Bell size={17} /><i /></button><div className="top-divider" /><span className="top-user">{staff?.name}<small>Fraud analyst</small></span><div className="avatar small-avatar">{staff?.name.split(' ').map((part) => part[0]).join('')}</div></div></header>
      <section className="page-content">
        {page === 'Overview' && <>
          <div className="page-heading"><div><span className="eyebrow">CONTROL ROOM <span className="heading-dot">/</span> INTERNAL OPERATIONS</span><h1>Good morning, {staff?.name.split(' ')[0]}</h1><p className="muted">Here’s the current read on your transaction landscape.</p></div><div className="heading-actions"><button className="button secondary" onClick={() => refresh()}><RefreshCw size={15} />Refresh</button><button className="button primary" onClick={generateDataset} disabled={busy}><Sparkles size={15} />Generate demo data</button></div></div>
          <div className="stat-grid"><Stat icon={<Database size={17} />} label="Transactions monitored" value={count(overview?.total_transactions)} hint="Across all demo profiles" color="mint" /><Stat icon={<ShieldAlert size={17} />} label="Open investigations" value={count(overview?.flagged_transactions)} hint="Require analyst review" color="amber" /><Stat icon={<AlertOctagon size={17} />} label="High / critical" value={count(overview?.high_critical_risk)} hint="Priority queue" color="coral" /><Stat icon={<Users size={17} />} label="Monitored profiles" value={count(overview?.total_users)} hint="Scenario coverage" color="blue" /></div>
          <div className="dashboard-grid"><section className="panel chart-panel"><div className="panel-heading"><div><span className="eyebrow">ACTIVITY</span><h3>Transaction volume</h3></div><span className="panel-period"><span className="health-dot" />ALL RECORDED</span></div><div className="chart-key"><span><i className="key-line" />Transactions per day</span><span>INR value</span></div><div className="chart-wrap">{overview?.activity_graph_data.length ? <ResponsiveContainer width="100%" height="100%"><AreaChart data={overview.activity_graph_data} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}><defs><linearGradient id="mintFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#43d9a3" stopOpacity={0.2} /><stop offset="95%" stopColor="#43d9a3" stopOpacity={0} /></linearGradient></defs><CartesianGrid stroke="#263532" strokeDasharray="3 6" vertical={false} /><XAxis dataKey="day" tickFormatter={(value: string) => value.slice(5)} stroke="#687974" tickLine={false} axisLine={false} fontSize={11} /><YAxis stroke="#687974" tickLine={false} axisLine={false} fontSize={11} /><Tooltip contentStyle={{ background: '#111a18', border: '1px solid #31443d', borderRadius: 4, color: '#e9f1ed' }} /><Area type="monotone" dataKey="count" stroke="#43d9a3" strokeWidth={2} fill="url(#mintFill)" /></AreaChart></ResponsiveContainer> : <div className="empty-chart"><Activity size={23} /><span>Generate demo data to populate activity</span></div>}</div><div className="chart-foot"><span>01 / TRANSACTIONS RECORDED</span><span>{overview?.activity_graph_data.length ?? 0} active days</span></div></section>
            <section className="panel queue-panel"><div className="panel-heading"><div><span className="eyebrow">NEEDS ATTENTION</span><h3>Priority queue</h3></div><button className="text-action" onClick={() => setPage('Fraud alerts')}>View all <ArrowUpRight size={14} /></button></div>{alerts.length ? <div className="queue-list">{alerts.slice(0, 5).map((item) => <button className="queue-item" key={item.transaction_id} onClick={() => openInvestigation(item.transaction_id)}><span className={`queue-marker ${item.risk_level.toLowerCase()}`} /><span className="queue-copy"><strong>{item.user_name}</strong><small>{item.transaction_id} · {item.location}</small></span><span className="queue-amount">{money(item.amount)}<RiskBadge level={item.risk_level} /></span></button>)}</div> : <Empty icon={<ShieldCheck size={23} />} title="Nothing in the queue" text="Generate demo data and run an analysis to raise an alert." action={<button className="button secondary" onClick={generateDataset}><Sparkles size={14} />Create demo data</button>} />}</section></div>
          <section className="panel scenario-panel"><div className="panel-heading"><div><span className="eyebrow">DEMO SCENARIOS</span><h3>Coverage at a glance</h3></div><button className="button secondary compact" onClick={analyzeAll} disabled={!users.length || busy}><Activity size={14} />Analyze all profiles</button></div><div className="scenario-grid">{scenarios.map((scenario) => { const user = users.find((item) => item.scenario === scenario.key); return <div className="scenario-row" key={scenario.key}><span className={`scenario-icon ${scenario.color}`}>{scenario.icon}</span><span className="scenario-copy"><strong>{scenario.label}</strong><small>{user ? user.user_id : 'Awaiting generated data'}</small></span><span className="scenario-result">{user ? `${user.flagged_count} flagged` : '—'}</span><button className="icon-button" title={user ? `Analyze ${user.user_id}` : 'Generate dataset first'} disabled={!user || busy} onClick={() => user && analyze(user.user_id)}><ArrowUpRight size={16} /></button></div> })}</div></section>
  </>}
        {page === 'Fraud alerts' && <><PageHeading eyebrow="INVESTIGATION QUEUE" title="Fraud alerts" description="Deterministic signals, with the evidence attached." action={<button className="button secondary" onClick={() => refresh()}><RefreshCw size={15} />Refresh queue</button>} /><div className="filter-bar"><label className="search-field"><Search size={16} /><input placeholder="Search transaction or profile" value={search} onChange={(event) => setSearch(event.target.value)} /></label><label className="select-wrap"><Filter size={15} /><select value={riskFilter} onChange={(event) => setRiskFilter(event.target.value)}><option value="ALL">All risk levels</option>{['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((level) => <option key={level}>{level}</option>)}</select><ChevronDown size={14} /></label><span className="result-count">{shownAlerts.length} investigations</span></div><div className="panel table-panel"><div className="table-scroll"><table><thead><tr><th>TRANSACTION</th><th>PROFILE</th><th>AMOUNT</th><th>SIGNAL EVIDENCE</th><th>RISK</th><th>STATUS</th><th /></tr></thead><tbody>{shownAlerts.map((item) => <tr key={item.transaction_id} onClick={() => openInvestigation(item.transaction_id)}><td><strong className="mono">{item.transaction_id}</strong><small>{dateTime(item.transaction_date)}</small></td><td><strong>{item.user_name}</strong><small>{item.user_id} · {item.location}</small></td><td className="amount-cell">{money(item.amount)}<small>{item.currency}</small></td><td><div className="signal-chips">{item.triggered_rules.map((rule) => <span key={rule}>{rule.replace('Transaction ', '').replace('Unusual ', '')}</span>)}</div></td><td><RiskBadge level={item.risk_level} /></td><td><StatusBadge status={item.status} /></td><td><button className="icon-button investigate-icon" title="Open investigation"><FileSearch size={16} /></button></td></tr>)}</tbody></table>{!shownAlerts.length && <Empty icon={<ShieldCheck size={23} />} title="No matching investigations" text={users.length ? 'Run analysis on a profile to surface explainable risk signals.' : 'Generate the demo dataset to begin exploring.'} />}</div></div></>}
        {page === 'Users' && <><PageHeading eyebrow="CUSTOMER PROFILES" title="Monitored users" description="Explore generated behavior patterns and run histories against active rules." action={<button className="button primary" onClick={generateDataset} disabled={busy}><Sparkles size={15} />Generate demo data</button>} /><div className="filter-bar"><label className="search-field"><Search size={16} /><input placeholder="Search ID, name, or email" value={search} onChange={(event) => setSearch(event.target.value)} /></label><span className="result-count">{shownUsers.length} profiles</span></div><div className="user-grid">{shownUsers.map((user) => <article className="panel user-card" key={user.user_id}><div className="user-card-top"><div className="profile-avatar">{initials(user.name)}</div><span className={`scenario-pill ${user.scenario}`}>{scenarioName(user.scenario)}</span></div><h3>{user.name}</h3><p className="mono user-id">{user.user_id} <span>·</span> {user.email}</p><div className="user-meta"><span><MapPin size={13} />{user.home_location}</span><span><Database size={13} />{user.transaction_count} transactions</span></div><div className="user-card-bottom"><span className="flagged-count"><b>{user.flagged_count}</b> flagged</span><button className="button secondary compact" onClick={() => analyze(user.user_id)} disabled={busy}><Activity size={14} />Run analysis</button></div></article>)}</div>{!shownUsers.length && <Empty icon={<Users size={24} />} title="No profiles yet" text="Generate the deterministic dataset to populate five investigation scenarios." action={<button className="button primary" onClick={generateDataset}><Sparkles size={14} />Generate demo data</button>} />}</>}
        {page === 'Transactions' && <><PageHeading eyebrow="LEDGER MONITOR" title="Transactions" description="Generated activity across the monitored cohort." action={<button className="button secondary" onClick={() => refresh()}><RefreshCw size={15} />Refresh</button>} /><div className="filter-bar"><label className="search-field"><Search size={16} /><input placeholder="Filter by ID, user, or location" value={search} onChange={(event) => setSearch(event.target.value)} /></label><span className="result-count">{shownTransactions.length} transactions</span></div><div className="panel table-panel"><div className="table-scroll"><table><thead><tr><th>TRANSACTION</th><th>PROFILE</th><th>AMOUNT</th><th>DATE & LOCATION</th><th>RISK</th><th>STATUS</th><th /></tr></thead><tbody>{shownTransactions.map((item) => <tr key={String(item.transaction_id)} onClick={() => item.risk_level && openInvestigation(String(item.transaction_id))}><td><strong className="mono">{String(item.transaction_id)}</strong><small>Device {String(item.device_id)}</small></td><td><strong>{String(item.user_name)}</strong><small>{String(item.user_id)}</small></td><td className="amount-cell">{money(Number(item.amount))}<small>{String(item.currency)}</small></td><td><strong>{String(item.location)}</strong><small>{dateTime(String(item.transaction_date))}</small></td><td>{item.risk_level ? <RiskBadge level={String(item.risk_level)} /> : <span className="muted">Not analyzed</span>}</td><td>{item.flag_status ? <StatusBadge status={String(item.flag_status)} /> : <span className="muted">—</span>}</td><td>{Boolean(item.risk_level) && <button className="icon-button investigate-icon" title="Open investigation"><FileSearch size={16} /></button>}</td></tr>)}</tbody></table></div></div></>}
        {page === 'Rules' && <><PageHeading eyebrow="DETERMINISTIC DETECTION" title="Fraud rules" description="Independent checks. Every signal explains what crossed its threshold." action={<span className="modular-label"><span className="health-dot" />MODULAR REGISTRY</span>} /><div className="rules-list">{rules.map((rule) => <article className="panel rule-card" key={String(rule.name)}><div className="rule-symbol"><Shield size={18} /></div><div className="rule-main"><div className="rule-title"><h3>{String(rule.name)}</h3><RiskBadge level={String(rule.severity)} /></div><p className="muted">{String(rule.description)}</p><div className="config-list">{Object.entries(rule.config as Record<string, unknown>).map(([key, value]) => <span key={key}><small>{key.replaceAll('_', ' ')}</small><b>{String(value)}</b></span>)}</div></div><label className="toggle-label"><span>{rule.enabled ? 'ACTIVE' : 'PAUSED'}</span><input type="checkbox" checked={Boolean(rule.enabled)} onChange={() => toggleRule(rule)} disabled={staff?.role !== 'admin'} /><i className="toggle-track" /></label></article>)}</div><div className="rule-note"><CircleHelp size={16} /><span>Rules are modular and extensible. Add a registered rule implementation to expand coverage.</span></div></>}
        {page === 'Activity log' && <><PageHeading eyebrow="SYSTEM TRACE" title="Audit activity" description="Chronological record of analysis and reviewer actions." action={<button className="button secondary" onClick={() => refresh()}><RefreshCw size={15} />Refresh log</button>} /><div className="panel activity-panel">{activity.length ? activity.map((event) => <div className="activity-row" key={String(event.id)}><span className="activity-marker"><Activity size={14} /></span><span className="activity-description"><strong>{String(event.event_type).replaceAll('_', ' ')}</strong><small>{String(event.staff_name || 'System')} {event.transaction_id ? `· ${String(event.transaction_id)}` : ''}</small></span><code>{dateTime(String(event.created_at))}</code><BadgeCheck size={15} className="audit-success" /></div>) : <Empty icon={<Activity size={23} />} title="No activity recorded" text="Analysis and review events will appear here." />}</div></>}
      </section>
      <footer className="app-footer"><span><ShieldCheck size={13} /> SENTINEL INTERNAL SYSTEM</span><span>DETERMINISTIC ANALYSIS <i /> BUILD 1.0.4</span></footer>
    </main>
    {mobileOpen && <div className="mobile-scrim" onClick={() => setMobileOpen(false)} />}
    {investigation && <div className="drawer-backdrop" onClick={() => setInvestigation(null)}><aside className="investigation-drawer" onClick={(event) => event.stopPropagation()}><div className="drawer-header"><div><span className="eyebrow">TRANSACTION INVESTIGATION</span><h2>{investigation.transaction.transaction_id}</h2></div><button className="icon-button" onClick={() => setInvestigation(null)} aria-label="Close investigation"><X size={20} /></button></div><div className="drawer-scroll"><div className="investigation-overview"><div><span className="eyebrow">AMOUNT</span><strong className="investigation-amount">{money(investigation.transaction.amount)}</strong><small>{investigation.transaction.currency}</small></div><div><RiskBadge level={investigation.transaction.risk_level || 'LOW'} /><StatusBadge status={investigation.transaction.flag_status || 'UNREVIEWED'} /></div></div><div className="detail-grid"><Detail label="Profile" value={`${investigation.transaction.user_id} · ${investigation.transaction.user_name}`} /><Detail label="Location" value={investigation.transaction.location} /><Detail label="Timestamp" value={dateTime(investigation.transaction.transaction_date)} /><Detail label="Device" value={investigation.transaction.device_id || '—'} /></div>{investigation.notifications?.length > 0 && <div className="notification-status"><Bell size={16} /><span>Notification delivery</span><div className="notification-channel-list">{(['SES', 'SNS'] as const).map((channel) => { const notification = investigation.notifications.find((item) => item.channel === channel); return <span key={channel}><b>{channel}</b><strong>{notification ? notification.status.toUpperCase() : 'NOT CONFIGURED'}</strong><small>{notification?.status === 'sent' ? `Sent to ${notification.recipient}` : notification?.status === 'failed' ? 'Delivery failed; see audit log.' : channel === 'SES' ? 'Configure sender and recipient in backend/.env.' : 'Configure topic ARN in backend/.env.'}</small></span> })}</div></div>}
      <section className="drawer-section evidence-section"><div className="drawer-section-heading"><div><span className="eyebrow">RULE EVALUATION</span><h3>Why it was flagged</h3></div><span className="evaluation-count">{investigation.rule_results.filter((rule) => rule.triggered).length}/{investigation.rule_results.length} TRIGGERED</span></div>{investigation.rule_results.length ? <div className="evidence-list">{investigation.rule_results.map((result) => <EvidenceCard result={result} key={result.rule_name} />)}</div> : <Empty icon={<Clock3 size={21} />} title="Not analyzed yet" text="Run analysis on this profile to evaluate all active rules." />}</section>
      <section className="drawer-section timeline-section"><span className="eyebrow">RECENT ACTIVITY</span><h3>Transaction history</h3><TransactionHistoryChart history={investigation.history} current={investigation.transaction} />{investigation.history.length ? <div className="mini-timeline">{investigation.history.map((item) => <div key={item.transaction_id}><i /><span><strong>{item.location} <small>{money(item.amount)}</small></strong><small>{item.transaction_id} · {dateTime(item.transaction_date)}</small></span></div>)}</div> : <p className="muted">No previous activity available.</p>}</section>
      <section className="review-section"><label htmlFor="review-comment">Analyst note <span>OPTIONAL</span></label><textarea id="review-comment" placeholder="Add context for the review record…" value={comment} onChange={(event) => setComment(event.target.value)} /><div className="review-actions"><button className="button secondary" onClick={() => submitReview('REVIEWED')} disabled={!investigation.transaction.fraud_flag_id}><Check size={17} />Mark reviewed</button><button className="button danger" onClick={() => submitReview('CLEARED')} disabled={!investigation.transaction.fraud_flag_id}><ShieldCheck size={17} />Clear transaction</button></div></section></div></aside></div>}
    {notice && <div className="toast"><span className="toast-mark"><Check size={14} /></span>{notice}<button className="icon-button" onClick={() => setNotice('')} aria-label="Dismiss"><X size={15} /></button></div>}
  </div>
}

function PageHeading({ eyebrow, title, description, action }: { eyebrow: string; title: string; description: string; action: ReactNode }) { return <div className="page-heading"><div><span className="eyebrow">{eyebrow}</span><h1>{title}</h1><p className="muted">{description}</p></div>{action && <div className="heading-actions">{action}</div>}</div> }
function Stat({ icon, label, value, hint, color }: { icon: ReactNode; label: string; value: string; hint: string; color: string }) { return <div className="panel stat-card"><div className={`stat-icon ${color}`}>{icon}</div><span className="stat-label">{label}</span><strong className="stat-value">{value}</strong><span className="stat-hint">{hint}</span></div> }
function RiskBadge({ level }: { level: string }) { return <span className={`risk-badge ${level.toLowerCase()}`}><i />{level}</span> }
function StatusBadge({ status }: { status: string }) { return <span className={`status-badge ${status.toLowerCase()}`}>{status.replace('_', ' ')}</span> }
function Detail({ label, value }: { label: string; value: string }) { return <div className="detail-item"><span>{label}</span><strong>{value}</strong></div> }
function Empty({ icon, title, text, action }: { icon: ReactNode; title: string; text: string; action?: ReactNode }) { return <div className="empty-state"><span>{icon}</span><strong>{title}</strong><p>{text}</p>{action}</div> }
function TransactionHistoryChart({ history, current }: { history: Investigation['history']; current: AlertRecord }) {
  const chartData = [...history, { transaction_id: current.transaction_id, transaction_date: current.transaction_date, location: current.location, latitude: current.latitude ?? 0, longitude: current.longitude ?? 0, amount: current.amount }].map((item, index) => ({ ...item, sequence: index + 1, label: `#${index + 1}` }))
  return <div className="investigation-chart"><div className="investigation-chart-heading"><span>AMOUNT BY TRANSACTION</span><strong>{chartData.length} recent transactions</strong></div><div className="investigation-chart-plot"><ResponsiveContainer width="100%" height="100%"><AreaChart data={chartData} margin={{ top: 14, right: 14, left: 0, bottom: 0 }}><defs><linearGradient id="historyFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#43d9a3" stopOpacity={0.25} /><stop offset="95%" stopColor="#43d9a3" stopOpacity={0.02} /></linearGradient></defs><CartesianGrid stroke="#26352e" strokeDasharray="3 5" vertical={false} /><XAxis dataKey="label" stroke="#8a9a90" tickLine={false} axisLine={false} fontSize={10} /><YAxis width={58} tickFormatter={(value: number) => `₹${Math.round(value / 1000)}k`} stroke="#8a9a90" tickLine={false} axisLine={false} fontSize={10} /><Tooltip contentStyle={{ background: '#111a15', border: '1px solid #385044', borderRadius: 4, color: '#edf4ef', fontSize: 12 }} formatter={(value) => [money(Number(value)), 'Amount']} labelFormatter={(label) => `Transaction ${label}`} /><Area type="monotone" dataKey="amount" stroke="#52d5a1" strokeWidth={2.5} fill="url(#historyFill)" activeDot={{ r: 5, fill: '#f18a68', stroke: '#101714', strokeWidth: 2 }} /></AreaChart></ResponsiveContainer></div><div className="chart-current-label"><span />Current transaction highlighted</div></div>
}
function EvidenceCard({ result }: { result: RuleResult }) {
  const evidence = result.evidence
  const detail = result.rule_name.includes('Velocity') ? `${evidence.transaction_count_in_window ?? 0} transactions in ${evidence.time_window_minutes ?? 5} minutes · threshold ${evidence.configured_threshold ?? 5}` : result.rule_name.includes('Amount') ? evidence.reason ? 'Not enough history to establish a baseline' : `${money(Number(evidence.current_amount))} vs ${money(Number(evidence.historical_baseline))} median · ${evidence.actual_deviation}× baseline (threshold ${evidence.configured_threshold}×)` : evidence.reason ? 'No previous transaction available for comparison' : `${evidence.previous_location} to ${evidence.current_location} · ${evidence.distance_km} km in ${evidence.time_difference_minutes} min · ${Number(evidence.required_speed_kmh).toLocaleString()} km/h required (limit ${evidence.max_plausible_speed_kmh} km/h)`
  const current = Number(evidence.current_amount ?? evidence.transaction_count_in_window ?? evidence.required_speed_kmh ?? 0)
  const threshold = Number(evidence.historical_baseline ?? evidence.configured_threshold ?? evidence.max_plausible_speed_kmh ?? 1)
  const currentWidth = `${Math.min(100, Math.max(8, current / Math.max(current, threshold) * 100))}%`
  const thresholdWidth = `${Math.min(100, Math.max(8, threshold / Math.max(current, threshold) * 100))}%`
  const isGeography = result.rule_name.includes('Geography')
  const previousCoordinates = typeof evidence.previous_latitude === 'number' ? `${Number(evidence.previous_latitude).toFixed(2)}°, ${Number(evidence.previous_longitude).toFixed(2)}°` : 'Previous location'
  const currentCoordinates = typeof evidence.current_latitude === 'number' ? `${Number(evidence.current_latitude).toFixed(2)}°, ${Number(evidence.current_longitude).toFixed(2)}°` : 'Current location'
  return <article className={`evidence-card ${result.triggered ? 'triggered' : ''}`}>
    <span className={`evidence-icon ${result.triggered ? 'is-triggered' : ''}`}>{result.triggered ? <AlertOctagon size={15} /> : <Check size={15} />}</span>
    <div className="evidence-copy"><div><strong>{result.rule_name}</strong><RiskBadge level={result.severity} /></div><p>{detail}</p>
      {isGeography ? <><div className="route-visual"><div className="route-endpoint"><i /><span>{String(evidence.previous_location ?? 'Previous location')}<small>{previousCoordinates}</small></span></div><div className="route-track"><span>{String(evidence.distance_km ?? '—')} km</span><i /></div><div className="route-endpoint destination"><i /><span>{String(evidence.current_location ?? 'Current location')}<small>{currentCoordinates}</small></span></div><svg className="route-spark" viewBox="0 0 320 35" preserveAspectRatio="none" aria-label="Transaction travel route"><path d="M4 25 C75 25 73 6 160 15 S242 29 316 8" /><circle cx="4" cy="25" r="3" /><circle cx="316" cy="8" r="3" /></svg></div><div className="evidence-visual"><div className="comparison-row"><span>REQUIRED</span><div className="comparison-track"><i className={result.triggered ? 'over' : ''} style={{ width: currentWidth }} /></div><b>{Number(evidence.required_speed_kmh ?? 0).toLocaleString()} km/h</b></div><div className="comparison-row"><span>MAX SPEED</span><div className="comparison-track"><i className="baseline" style={{ width: thresholdWidth }} /></div><b>{String(evidence.max_plausible_speed_kmh ?? '—')} km/h</b></div></div></> : <div className="evidence-visual"><div className="comparison-row"><span>{result.rule_name.includes('Velocity') ? 'OBSERVED' : 'CURRENT'}</span><div className="comparison-track"><i className={result.triggered ? 'over' : ''} style={{ width: currentWidth }} /></div><b>{result.rule_name.includes('Amount') ? money(current) : `${current} tx`}</b></div><div className="comparison-row"><span>{result.rule_name.includes('Amount') ? 'MEDIAN' : 'LIMIT'}</span><div className="comparison-track"><i className="baseline" style={{ width: thresholdWidth }} /></div><b>{result.rule_name.includes('Amount') ? money(threshold) : `${threshold} tx`}</b></div></div>}
      {Array.isArray(evidence.relevant_transaction_ids) && <small className="evidence-ids">Transactions: {(evidence.relevant_transaction_ids as string[]).join(', ')}</small>}
    </div><span className={`evaluation-state ${result.triggered ? 'yes' : ''}`}>{result.triggered ? 'TRIGGERED' : 'CLEAR'}</span>
  </article>
}
function scenarioName(value: string) { return ({ normal: 'BASELINE', high_amount: 'HIGH AMOUNT', high_velocity: 'VELOCITY', impossible_travel: 'GEOGRAPHY', multiple_signals: 'MULTI-SIGNAL' } as Record<string, string>)[value] || value.toUpperCase() }
function initials(name: string) { return name.split(' ').map((part) => part[0]).join('') }
function money(value: number) { return `₹${Number(value || 0).toLocaleString('en-IN', { maximumFractionDigits: 0 })}` }
function count(value?: number) { return String(value ?? 0).padStart(2, '0') }
function dateTime(value: string) { const date = new Date(value); return Number.isNaN(date.getTime()) ? value : new Intl.DateTimeFormat('en-IN', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit', hour12: false }).format(date) }

export default App
