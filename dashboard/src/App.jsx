import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Ban,
  BarChart3,
  CheckCircle2,
  Clock3,
  Database,
  Eye,
  FileText,
  Gauge,
  Lock,
  LogIn,
  LogOut,
  Network,
  RefreshCw,
  RotateCcw,
  Search,
  ShieldAlert,
  ShieldCheck,
  Smartphone,
  UserCircle,
  X
} from "lucide-react";

import {
  API_BASE_URL,
  activateDevice,
  getCurrentAdmin,
  getAuthenticationEvents,
  getDevices,
  getHealth,
  getPerformanceSummary,
  loginAdmin,
  logoutAdmin,
  revokeDevice,
  suspendDevice
} from "./api";

const NAV_ITEMS = [
  {
    id: "overview",
    label: "Overview",
    icon: Gauge
  },
  {
    id: "devices",
    label: "Devices",
    icon: Smartphone
  },
  {
    id: "audit",
    label: "Authentication Audit",
    icon: FileText
  },
  {
    id: "alerts",
    label: "Spoofing Alerts",
    icon: ShieldAlert
  },
  {
    id: "performance",
    label: "Performance",
    icon: BarChart3
  }
];

const DEVICE_STATUSES = ["ALL", "ACTIVE", "SUSPENDED", "REVOKED"];
const DECISIONS = ["ALL", "GRANTED", "DENIED"];
const SPOOFING_FILTERS = [
  "ALL",
  "NONE",
  "MAC_MISMATCH",
  "IP_MISMATCH",
  "MAC_AND_IP_MISMATCH",
  "CONTEXT_INCOMPLETE",
  "NOT_EVALUATED"
];
const SPOOFING_INCIDENTS = new Set([
  "MAC_MISMATCH",
  "IP_MISMATCH",
  "MAC_AND_IP_MISMATCH"
]);

function formatDate(value) {
  if (!value) {
    return "Not recorded";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return date.toLocaleString();
}

function formatMetric(value, suffix = "") {
  if (value === null || value === undefined || Number.isNaN(Number(value))) {
    return "Unavailable";
  }

  return `${Number(value).toLocaleString(undefined, {
    maximumFractionDigits: 3
  })}${suffix}`;
}

function formatPercent(value) {
  return formatMetric(value, "%");
}

function formatMs(value) {
  return formatMetric(value, " ms");
}

function shortId(value) {
  if (!value || value.length <= 18) {
    return value || "Not recorded";
  }

  return `${value.slice(0, 12)}...${value.slice(-6)}`;
}

function valueOrDash(value) {
  if (value === null || value === undefined || value === "") {
    return "Not recorded";
  }

  return value;
}

function normalize(value) {
  return String(value || "").toLowerCase();
}

function getDeviceStatus(device) {
  return String(device?.status || "UNKNOWN").toUpperCase();
}

function getEventDecision(event) {
  return String(event?.decision || "UNKNOWN").toUpperCase();
}

function getSpoofingClassification(event) {
  return String(event?.spoofingClassification || "NOT_EVALUATED")
    .toUpperCase();
}

function sortByTimestampDescending(items) {
  return [...items].sort((left, right) => {
    const leftTime = new Date(left.timestamp || left.updatedAt || 0).getTime();
    const rightTime = new Date(right.timestamp || right.updatedAt || 0).getTime();

    return rightTime - leftTime;
  });
}

function calculateStats(devices, events) {
  const deviceList = Array.isArray(devices) ? devices : null;
  const eventList = Array.isArray(events) ? events : null;
  const totalEvents = eventList?.length ?? null;
  const grantedAttempts = eventList
    ? eventList.filter((event) => getEventDecision(event) === "GRANTED").length
    : null;
  const deniedAttempts = eventList
    ? eventList.filter((event) => getEventDecision(event) === "DENIED").length
    : null;
  const spoofingIncidents = eventList
    ? eventList.filter((event) =>
      SPOOFING_INCIDENTS.has(getSpoofingClassification(event))
    ).length
    : null;
  const successRate = totalEvents
    ? Number(((grantedAttempts / totalEvents) * 100).toFixed(1))
    : null;

  return {
    totalDevices: deviceList?.length ?? null,
    activeDevices: deviceList
      ? deviceList.filter((device) => getDeviceStatus(device) === "ACTIVE")
        .length
      : null,
    suspendedDevices: deviceList
      ? deviceList.filter((device) => getDeviceStatus(device) === "SUSPENDED")
        .length
      : null,
    revokedDevices: deviceList
      ? deviceList.filter((device) => getDeviceStatus(device) === "REVOKED")
        .length
      : null,
    totalEvents,
    grantedAttempts,
    deniedAttempts,
    spoofingIncidents,
    successRate
  };
}

function StatCard({ icon: Icon, label, value, detail, tone = "neutral" }) {
  return (
    <section className={`stat-card tone-${tone}`}>
      <div className="stat-icon">
        <Icon size={20} aria-hidden="true" />
      </div>
      <div>
        <p className="stat-label">{label}</p>
        <strong className="stat-value">
          {value === null || value === undefined ? "Unavailable" : value}
        </strong>
        {detail ? <p className="stat-detail">{detail}</p> : null}
      </div>
    </section>
  );
}

function StatusBadge({ value }) {
  const status = String(value || "UNKNOWN").toUpperCase();

  return <span className={`badge status-${status}`}>{status}</span>;
}

function DecisionBadge({ value }) {
  const decision = String(value || "UNKNOWN").toUpperCase();

  return <span className={`badge decision-${decision}`}>{decision}</span>;
}

function SpoofingBadge({ value }) {
  const classification = String(value || "NOT_EVALUATED").toUpperCase();

  return (
    <span className={`badge spoofing-${classification}`}>
      {classification}
    </span>
  );
}

function ErrorState({ message }) {
  return (
    <div className="state-message state-error" role="alert">
      <AlertTriangle size={18} aria-hidden="true" />
      <span>{message}</span>
    </div>
  );
}

function EmptyState({ message }) {
  return (
    <div className="state-message">
      <Clock3 size={18} aria-hidden="true" />
      <span>{message}</span>
    </div>
  );
}

function SegmentedControl({ label, options, value, onChange }) {
  return (
    <label className="control-group">
      <span>{label}</span>
      <select value={value} onChange={(event) => onChange(event.target.value)}>
        {options.map((option) => (
          <option key={option} value={option}>
            {option}
          </option>
        ))}
      </select>
    </label>
  );
}

function SearchBox({ value, onChange, placeholder }) {
  return (
    <label className="search-box">
      <Search size={17} aria-hidden="true" />
      <input
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        type="search"
      />
    </label>
  );
}

function HealthPanel({ health, error }) {
  const apiStatus = error ? "unavailable" : health?.api || "unavailable";
  const fabricStatus = error
    ? "unavailable"
    : health?.fabric || "unavailable";

  return (
    <section className="panel">
      <div className="panel-heading">
        <div>
          <h2>System Health</h2>
          <p>REST gateway and ledger evaluation status.</p>
        </div>
        <Network size={22} aria-hidden="true" />
      </div>
      {error ? <ErrorState message={error} /> : null}
      <div className="health-grid">
        <div className="health-item">
          <span>API</span>
          <StatusBadge value={apiStatus === "healthy" ? "ACTIVE" : "REVOKED"} />
          <strong>{apiStatus}</strong>
        </div>
        <div className="health-item">
          <span>Fabric</span>
          <StatusBadge
            value={fabricStatus === "connected" ? "ACTIVE" : "REVOKED"}
          />
          <strong>{fabricStatus}</strong>
        </div>
      </div>
    </section>
  );
}

function Overview({ health, errors, stats, events }) {
  const recentEvents = sortByTimestampDescending(events || []).slice(0, 5);

  return (
    <div className="view-stack">
      <div className="stat-grid">
        <StatCard
          icon={Database}
          label="Total Devices"
          value={stats.totalDevices}
          detail="Registered identities"
        />
        <StatCard
          icon={ShieldCheck}
          label="Active Devices"
          value={stats.activeDevices}
          tone="success"
        />
        <StatCard
          icon={Ban}
          label="Suspended Devices"
          value={stats.suspendedDevices}
          tone="warning"
        />
        <StatCard
          icon={Lock}
          label="Revoked Devices"
          value={stats.revokedDevices}
          tone="danger"
        />
        <StatCard
          icon={Activity}
          label="Authentication Events"
          value={stats.totalEvents}
          detail={
            stats.successRate === null
              ? "Success rate unavailable"
              : `${stats.successRate}% success rate`
          }
        />
        <StatCard
          icon={CheckCircle2}
          label="Granted Attempts"
          value={stats.grantedAttempts}
          tone="success"
        />
        <StatCard
          icon={AlertTriangle}
          label="Denied Attempts"
          value={stats.deniedAttempts}
          tone="warning"
        />
        <StatCard
          icon={ShieldAlert}
          label="Spoofing Incidents"
          value={stats.spoofingIncidents}
          tone="danger"
        />
      </div>

      <div className="overview-grid">
        <HealthPanel health={health} error={errors.health} />
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Recent Authentication</h2>
              <p>Latest immutable authentication decisions.</p>
            </div>
            <FileText size={22} aria-hidden="true" />
          </div>
          {errors.audit ? <ErrorState message={errors.audit} /> : null}
          {!errors.audit && recentEvents.length === 0 ? (
            <EmptyState message="No authentication events returned." />
          ) : null}
          {recentEvents.length > 0 ? (
            <div className="compact-list">
              {recentEvents.map((event) => (
                <article key={event.eventId} className="list-row">
                  <div>
                    <strong>{shortId(event.did)}</strong>
                    <span>{formatDate(event.timestamp)}</span>
                  </div>
                  <div className="badge-row">
                    <DecisionBadge value={event.decision} />
                    <SpoofingBadge value={event.spoofingClassification} />
                  </div>
                </article>
              ))}
            </div>
          ) : null}
        </section>
      </div>
    </div>
  );
}

function DeviceActions({ device, onAction, canManage }) {
  const status = getDeviceStatus(device);

  if (!canManage) {
    return <span className="muted">View only</span>;
  }

  if (status === "REVOKED") {
    return <span className="muted">No actions</span>;
  }

  return (
    <div className="row-actions">
      {status === "ACTIVE" ? (
        <button
          className="button button-muted"
          onClick={() => onAction(device, "suspend")}
          title="Suspend device"
          type="button"
        >
          <Ban size={16} aria-hidden="true" />
          Suspend
        </button>
      ) : null}
      {status === "SUSPENDED" ? (
        <button
          className="button button-muted"
          onClick={() => onAction(device, "activate")}
          title="Activate device"
          type="button"
        >
          <RotateCcw size={16} aria-hidden="true" />
          Activate
        </button>
      ) : null}
      <button
        className="button button-danger"
        onClick={() => onAction(device, "revoke")}
        title="Revoke device"
        type="button"
      >
        <Lock size={16} aria-hidden="true" />
        Revoke
      </button>
    </div>
  );
}

function DevicesView({
  devices,
  error,
  deviceSearch,
  setDeviceSearch,
  deviceStatusFilter,
  setDeviceStatusFilter,
  selectedDevice,
  setSelectedDevice,
  canManageDevices,
  onAction
}) {
  const filteredDevices = useMemo(() => {
    const list = Array.isArray(devices) ? devices : [];
    const query = normalize(deviceSearch);

    return list.filter((device) => {
      const matchesStatus = deviceStatusFilter === "ALL" ||
        getDeviceStatus(device) === deviceStatusFilter;
      const matchesSearch = !query ||
        normalize(device.did).includes(query) ||
        normalize(device.owner).includes(query) ||
        normalize(device.registeredMacAddress).includes(query) ||
        normalize(device.registeredIpAddress).includes(query);

      return matchesStatus && matchesSearch;
    });
  }, [devices, deviceSearch, deviceStatusFilter]);

  return (
    <div className="view-stack">
      <section className="panel">
        <div className="panel-heading table-heading">
          <div>
            <h2>Registered Devices</h2>
            <p>Blockchain identity records returned by the gateway API.</p>
          </div>
          <div className="filter-row">
            <SearchBox
              value={deviceSearch}
              onChange={setDeviceSearch}
              placeholder="Search DID, owner, MAC, IP"
            />
            <SegmentedControl
              label="Status"
              options={DEVICE_STATUSES}
              value={deviceStatusFilter}
              onChange={setDeviceStatusFilter}
            />
          </div>
        </div>
        {error ? <ErrorState message={error} /> : null}
        {!error && devices && filteredDevices.length === 0 ? (
          <EmptyState message="No devices match the current filters." />
        ) : null}
        {!error && devices ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>DID</th>
                  <th>Owner</th>
                  <th>Registered MAC</th>
                  <th>Registered IP</th>
                  <th>Status</th>
                  <th>Registered</th>
                  <th>Updated</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredDevices.map((device) => (
                  <tr key={device.did}>
                    <td className="mono-cell" title={device.did}>
                      {shortId(device.did)}
                    </td>
                    <td>{valueOrDash(device.owner)}</td>
                    <td>{valueOrDash(device.registeredMacAddress)}</td>
                    <td>{valueOrDash(device.registeredIpAddress)}</td>
                    <td>
                      <StatusBadge value={device.status} />
                    </td>
                    <td>{formatDate(device.registeredAt)}</td>
                    <td>{formatDate(device.updatedAt)}</td>
                    <td>
                      <div className="row-actions">
                        <button
                          className="icon-button"
                          onClick={() => setSelectedDevice(device)}
                          title="View device details"
                          type="button"
                        >
                          <Eye size={17} aria-hidden="true" />
                          <span className="sr-only">View details</span>
                        </button>
                        <DeviceActions
                          device={device}
                          onAction={onAction}
                          canManage={canManageDevices}
                        />
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </section>

      {selectedDevice ? (
        <DeviceDetails
          device={selectedDevice}
          onClose={() => setSelectedDevice(null)}
          canManageDevices={canManageDevices}
          onAction={onAction}
        />
      ) : null}
    </div>
  );
}

function DetailItem({ label, value }) {
  return (
    <div className="detail-item">
      <span>{label}</span>
      <strong>{valueOrDash(value)}</strong>
    </div>
  );
}

function DeviceDetails({ device, onClose, canManageDevices, onAction }) {
  return (
    <section className="panel details-panel">
      <div className="panel-heading">
        <div>
          <h2>Device Details</h2>
          <p>{device.did}</p>
        </div>
        <button
          className="icon-button"
          onClick={onClose}
          title="Close details"
          type="button"
        >
          <X size={18} aria-hidden="true" />
          <span className="sr-only">Close details</span>
        </button>
      </div>
      <div className="detail-grid">
        <DetailItem label="Owner" value={device.owner} />
        <DetailItem label="Status" value={<StatusBadge value={device.status} />} />
        <DetailItem
          label="Registered MAC"
          value={device.registeredMacAddress}
        />
        <DetailItem label="Registered IP" value={device.registeredIpAddress} />
        <DetailItem label="Registered At" value={formatDate(device.registeredAt)} />
        <DetailItem label="Updated At" value={formatDate(device.updatedAt)} />
        <DetailItem label="Revoked At" value={formatDate(device.revokedAt)} />
        <DetailItem label="Revocation Reason" value={device.revocationReason} />
        <DetailItem label="Suspension Reason" value={device.suspensionReason} />
        <DetailItem label="Transaction ID" value={device.transactionId} />
        <DetailItem label="Last Transaction ID" value={device.lastTransactionId} />
      </div>
      <div className="public-key">
        <span>Public Key</span>
        <pre>{valueOrDash(device.publicKey)}</pre>
      </div>
      <div className="details-actions">
        <DeviceActions
          device={device}
          onAction={onAction}
          canManage={canManageDevices}
        />
      </div>
    </section>
  );
}

function AuditFilters({
  decisionFilter,
  setDecisionFilter,
  spoofingFilter,
  setSpoofingFilter,
  auditSearch,
  setAuditSearch
}) {
  return (
    <div className="filter-row">
      <SearchBox
        value={auditSearch}
        onChange={setAuditSearch}
        placeholder="Search event ID, DID, reason"
      />
      <SegmentedControl
        label="Decision"
        options={DECISIONS}
        value={decisionFilter}
        onChange={setDecisionFilter}
      />
      <SegmentedControl
        label="Spoofing"
        options={SPOOFING_FILTERS}
        value={spoofingFilter}
        onChange={setSpoofingFilter}
      />
    </div>
  );
}

function useFilteredAudit(events, decisionFilter, spoofingFilter, auditSearch) {
  return useMemo(() => {
    const list = sortByTimestampDescending(Array.isArray(events) ? events : []);
    const query = normalize(auditSearch);

    return list.filter((event) => {
      const decision = getEventDecision(event);
      const classification = getSpoofingClassification(event);
      const matchesDecision = decisionFilter === "ALL" ||
        decision === decisionFilter;
      const matchesSpoofing = spoofingFilter === "ALL" ||
        classification === spoofingFilter;
      const matchesSearch = !query ||
        normalize(event.eventId).includes(query) ||
        normalize(event.did).includes(query) ||
        normalize(event.reason).includes(query) ||
        normalize(event.transactionId).includes(query);

      return matchesDecision && matchesSpoofing && matchesSearch;
    });
  }, [auditSearch, decisionFilter, events, spoofingFilter]);
}

function AuditView({
  events,
  error,
  decisionFilter,
  setDecisionFilter,
  spoofingFilter,
  setSpoofingFilter,
  auditSearch,
  setAuditSearch
}) {
  const filteredEvents = useFilteredAudit(
    events,
    decisionFilter,
    spoofingFilter,
    auditSearch
  );

  return (
    <section className="panel">
      <div className="panel-heading table-heading">
        <div>
          <h2>Authentication Audit</h2>
          <p>Immutable authentication events from the audit API.</p>
        </div>
        <AuditFilters
          decisionFilter={decisionFilter}
          setDecisionFilter={setDecisionFilter}
          spoofingFilter={spoofingFilter}
          setSpoofingFilter={setSpoofingFilter}
          auditSearch={auditSearch}
          setAuditSearch={setAuditSearch}
        />
      </div>
      {error ? <ErrorState message={error} /> : null}
      {!error && events && filteredEvents.length === 0 ? (
        <EmptyState message="No audit events match the current filters." />
      ) : null}
      {!error && events ? <AuditTable events={filteredEvents} /> : null}
    </section>
  );
}

function AuditTable({ events, compact = false }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Event ID</th>
            <th>DID</th>
            <th>Decision</th>
            <th>Reason</th>
            <th>Observed MAC</th>
            <th>Observed IP</th>
            <th>Spoofing</th>
            <th>Transaction ID</th>
          </tr>
        </thead>
        <tbody>
          {events.map((event) => (
            <tr key={event.eventId}>
              <td>{formatDate(event.timestamp)}</td>
              <td className="mono-cell" title={event.eventId}>
                {shortId(event.eventId)}
              </td>
              <td className="mono-cell" title={event.did}>
                {shortId(event.did)}
              </td>
              <td>
                <DecisionBadge value={event.decision} />
              </td>
              <td>{valueOrDash(event.reason)}</td>
              <td>{valueOrDash(event.observedMacAddress)}</td>
              <td>{valueOrDash(event.observedIpAddress)}</td>
              <td>
                <SpoofingBadge value={event.spoofingClassification} />
              </td>
              <td className="mono-cell" title={event.transactionId}>
                {compact
                  ? shortId(event.transactionId)
                  : valueOrDash(shortId(event.transactionId))}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function SpoofingAlertsView({ events, error }) {
  const alerts = useMemo(() => {
    return sortByTimestampDescending(Array.isArray(events) ? events : [])
      .filter((event) =>
        SPOOFING_INCIDENTS.has(getSpoofingClassification(event))
      );
  }, [events]);

  return (
    <section className="panel">
      <div className="panel-heading">
        <div>
          <h2>Spoofing Alerts</h2>
          <p>Confirmed MAC/IP mismatch events from immutable audit records.</p>
        </div>
        <ShieldAlert size={22} aria-hidden="true" />
      </div>
      {error ? <ErrorState message={error} /> : null}
      {!error && events && alerts.length === 0 ? (
        <EmptyState message="No confirmed spoofing incidents returned." />
      ) : null}
      {!error && events && alerts.length > 0 ? (
        <AuditTable events={alerts} compact />
      ) : null}
    </section>
  );
}

function RequirementBadge({ value }) {
  if (value === null || value === undefined) {
    return <span className="badge spoofing-NOT_EVALUATED">UNAVAILABLE</span>;
  }

  return value ? (
    <span className="badge decision-GRANTED">PASS</span>
  ) : (
    <span className="badge decision-DENIED">FAIL</span>
  );
}

function PerformanceTable({ results }) {
  const rows = ["1", "10", "25", "50"]
    .map((level) => ({
      level,
      result: results?.[level]
    }))
    .filter((row) => row.result);

  if (rows.length === 0) {
    return <EmptyState message="No evaluation data available." />;
  }

  return (
    <div className="table-wrap">
      <table className="performance-table">
        <thead>
          <tr>
            <th>Concurrency</th>
            <th>Success Rate</th>
            <th>Mean Latency</th>
            <th>Median</th>
            <th>P95</th>
            <th>Throughput</th>
            <th>Latency Increase</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(({ level, result }) => (
            <tr key={level}>
              <td>{level}</td>
              <td>{formatPercent(result.successRatePercent)}</td>
              <td>{formatMs(result.meanLatencyMs)}</td>
              <td>{formatMs(result.medianLatencyMs)}</td>
              <td>{formatMs(result.p95LatencyMs)}</td>
              <td>
                {formatMetric(result.throughputPerSecond, " auth/s")}
              </td>
              <td>
                {formatPercent(
                  result.latencyIncreaseVsConcurrency1Percent
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function PerformanceView({ performance, health, error }) {
  const live = performance?.live || {};
  const formal = performance?.formal || {};
  const level50 = formal.results?.["50"] || null;
  const requirementStatus = formal.requirementStatus || {};

  return (
    <div className="view-stack">
      {error ? <ErrorState message={error} /> : null}
      <div className="stat-grid">
        <StatCard
          icon={Network}
          label="Fabric Health"
          value={health?.fabric || "Unavailable"}
          detail={health?.api ? `API ${health.api}` : null}
        />
        <StatCard
          icon={CheckCircle2}
          label="Live Success Rate"
          value={formatPercent(live.successRatePercent)}
          detail={`${live.grantedSinceStart || 0} granted / ${live.deniedSinceStart || 0} denied`}
          tone="success"
        />
        <StatCard
          icon={Clock3}
          label="Recent Mean Latency"
          value={formatMs(live.meanRecentAuthenticationLatencyMs)}
          detail="Process-lifetime sample"
        />
        <StatCard
          icon={Activity}
          label="Observed Authentication Throughput"
          value={formatMetric(live.recentThroughputPerSecond, " auth/s")}
          detail={`${live.recentThroughputWindowSeconds || 60}s live window`}
        />
        <StatCard
          icon={Gauge}
          label="Formal P95 Latency"
          value={formatMs(level50?.p95LatencyMs)}
          detail="50-concurrent result"
        />
        <StatCard
          icon={ShieldAlert}
          label="Avg Spoofing Check"
          value={formatMs(
            level50?.spoofingCheckDurationMs?.mean ??
              live.meanRecentSpoofingCheckDurationMs
          )}
        />
        <StatCard
          icon={BarChart3}
          label="50 Concurrent"
          value={
            formal.requirement50Concurrent
              ? formal.requirement50Concurrent.passed ? "PASS" : "FAIL"
              : "Unavailable"
          }
          detail={formal.fileName || "No formal concurrency summary"}
          tone={
            formal.requirement50Concurrent?.passed
              ? "success"
              : "warning"
          }
        />
        <StatCard
          icon={FileText}
          label="Last Evaluation"
          value={formatDate(formal.evaluationDate)}
        />
      </div>

      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2>Requirement Status</h2>
            <p>Calculated from measured concurrency results.</p>
          </div>
          <BarChart3 size={22} aria-hidden="true" />
        </div>
        {!formal.available ? (
          <EmptyState message={formal.message || "No evaluation data available."} />
        ) : (
          <div className="requirement-grid">
            <div className="requirement-item">
              <span>Authentication &lt;= 5 s</span>
              <RequirementBadge
                value={requirementStatus.authenticationUnder5Seconds}
              />
            </div>
            <div className="requirement-item">
              <span>Spoofing &lt;= 3 s</span>
              <RequirementBadge value={requirementStatus.spoofingUnder3Seconds} />
            </div>
            <div className="requirement-item">
              <span>50 concurrent</span>
              <RequirementBadge value={requirementStatus.fiftyConcurrent} />
            </div>
          </div>
        )}
      </section>

      <section className="panel">
        <div className="panel-heading table-heading">
          <div>
            <h2>Formal Evaluation Metrics</h2>
            <p>Concurrency summary generated by the Phase 11 harness.</p>
          </div>
        </div>
        {!formal.available ? (
          <EmptyState message={formal.message || "No evaluation data available."} />
        ) : (
          <PerformanceTable results={formal.results} />
        )}
      </section>

      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2>Live Operational Metrics</h2>
            <p>{live.persistence || "Process-lifetime metrics."}</p>
          </div>
          <Activity size={22} aria-hidden="true" />
        </div>
        <div className="detail-grid">
          <DetailItem
            label="Attempts Since Start"
            value={live.totalAttemptsSinceStart}
          />
          <DetailItem
            label="Recent P95"
            value={formatMs(live.p95RecentAuthenticationLatencyMs)}
          />
          <DetailItem
            label="Last Authentication"
            value={formatDate(live.lastAuthenticationAt)}
          />
        </div>
      </section>
    </div>
  );
}

function ActionModal({
  actionState,
  reason,
  setReason,
  busy,
  error,
  onCancel,
  onConfirm
}) {
  if (!actionState) {
    return null;
  }

  const { action, device } = actionState;
  const requiresReason = action === "suspend" || action === "revoke";
  const title = action === "activate"
    ? "Activate Device"
    : action === "suspend"
      ? "Suspend Device"
      : "Revoke Device";
  const isRevoke = action === "revoke";

  return (
    <div className="modal-backdrop" role="presentation">
      <section
        aria-labelledby="device-action-title"
        className="modal"
        role="dialog"
      >
        <div className="modal-heading">
          <div>
            <h2 id="device-action-title">{title}</h2>
            <p>{device.did}</p>
          </div>
          <button
            className="icon-button"
            onClick={onCancel}
            title="Close dialog"
            type="button"
          >
            <X size={18} aria-hidden="true" />
            <span className="sr-only">Close dialog</span>
          </button>
        </div>

        {isRevoke ? (
          <div className="state-message state-error">
            <AlertTriangle size={18} aria-hidden="true" />
            <span>Revoked devices cannot be reactivated by the backend.</span>
          </div>
        ) : null}

        {requiresReason ? (
          <label className="reason-field">
            <span>Reason</span>
            <textarea
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              rows={4}
            />
          </label>
        ) : (
          <p className="modal-copy">
            The device status will be changed and the table will refresh.
          </p>
        )}

        {error ? <ErrorState message={error} /> : null}

        <div className="modal-actions">
          <button
            className="button button-muted"
            onClick={onCancel}
            disabled={busy}
            type="button"
          >
            Cancel
          </button>
          <button
            className={isRevoke ? "button button-danger" : "button"}
            onClick={onConfirm}
            disabled={busy || (requiresReason && reason.trim() === "")}
            type="button"
          >
            {busy ? "Working" : title}
          </button>
        </div>
      </section>
    </div>
  );
}

function LoginView({ busy, error, onLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  function handleSubmit(event) {
    event.preventDefault();
    onLogin(username, password);
  }

  return (
    <main className="login-shell">
      <form className="login-panel" onSubmit={handleSubmit}>
        <div className="login-brand">
          <div className="brand-mark">
            <ShieldCheck size={26} aria-hidden="true" />
          </div>
          <div>
            <p className="eyebrow">Administrator Login</p>
            <h1>Blockchain Authentication Console</h1>
          </div>
        </div>

        <label className="login-field">
          <span>Username</span>
          <input
            autoComplete="username"
            name="username"
            onChange={(event) => setUsername(event.target.value)}
            required
            type="text"
            value={username}
          />
        </label>

        <label className="login-field">
          <span>Password</span>
          <input
            autoComplete="current-password"
            name="password"
            onChange={(event) => setPassword(event.target.value)}
            required
            type="password"
            value={password}
          />
        </label>

        {error ? <ErrorState message={error} /> : null}

        <button
          className="button login-button"
          disabled={busy}
          type="submit"
        >
          <LogIn size={17} aria-hidden="true" />
          {busy ? "Signing in" : "Sign in"}
        </button>

        <p className="login-api">{API_BASE_URL}</p>
      </form>
    </main>
  );
}

function isUnauthorizedResult(result) {
  return result.status === "rejected" && result.reason?.status === 401;
}

function App() {
  const [admin, setAdmin] = useState(null);
  const [authChecked, setAuthChecked] = useState(false);
  const [authError, setAuthError] = useState("");
  const [loginBusy, setLoginBusy] = useState(false);
  const [activeView, setActiveView] = useState("overview");
  const [health, setHealth] = useState(null);
  const [devices, setDevices] = useState(null);
  const [events, setEvents] = useState(null);
  const [performance, setPerformance] = useState(null);
  const [errors, setErrors] = useState({});
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [lastRefreshed, setLastRefreshed] = useState(null);
  const [deviceSearch, setDeviceSearch] = useState("");
  const [deviceStatusFilter, setDeviceStatusFilter] = useState("ALL");
  const [auditSearch, setAuditSearch] = useState("");
  const [decisionFilter, setDecisionFilter] = useState("ALL");
  const [spoofingFilter, setSpoofingFilter] = useState("ALL");
  const [selectedDevice, setSelectedDevice] = useState(null);
  const [actionState, setActionState] = useState(null);
  const [actionReason, setActionReason] = useState("");
  const [actionError, setActionError] = useState("");
  const [actionBusy, setActionBusy] = useState(false);

  const refreshData = useCallback(async () => {
    setRefreshing(true);
    setErrors({});

    const [healthResult, devicesResult, auditResult, performanceResult] =
      await Promise.allSettled([
        getHealth(),
        getDevices(),
        getAuthenticationEvents(),
        getPerformanceSummary()
      ]);
    const nextErrors = {};

    if (
      isUnauthorizedResult(devicesResult) ||
      isUnauthorizedResult(auditResult) ||
      isUnauthorizedResult(performanceResult)
    ) {
      setAdmin(null);
      setAuthError("Your administrator session has expired");
      setHealth(null);
      setDevices(null);
      setEvents(null);
      setPerformance(null);
      setSelectedDevice(null);
      setLoading(false);
      setRefreshing(false);
      return;
    }

    if (healthResult.status === "fulfilled") {
      setHealth(healthResult.value);
    } else {
      setHealth(null);
      nextErrors.health = healthResult.reason.message;
    }

    if (devicesResult.status === "fulfilled") {
      const deviceData = devicesResult.value.data || [];
      setDevices(deviceData);
      setSelectedDevice((current) => {
        if (!current) {
          return null;
        }

        return deviceData.find((device) => device.did === current.did) || null;
      });
    } else {
      setDevices(null);
      setSelectedDevice(null);
      nextErrors.devices = devicesResult.reason.message;
    }

    if (auditResult.status === "fulfilled") {
      setEvents(auditResult.value.data || []);
    } else {
      setEvents(null);
      nextErrors.audit = auditResult.reason.message;
    }

    if (performanceResult.status === "fulfilled") {
      setPerformance(performanceResult.value.data || null);
    } else {
      setPerformance(null);
      nextErrors.performance = performanceResult.reason.message;
    }

    setErrors(nextErrors);
    setLastRefreshed(new Date());
    setLoading(false);
    setRefreshing(false);
  }, []);

  useEffect(() => {
    let active = true;

    async function checkCurrentAdmin() {
      try {
        const currentAdmin = await getCurrentAdmin();

        if (active) {
          setAdmin(currentAdmin.data.admin);
          setAuthError("");
        }
      } catch (error) {
        if (active && error.status !== 401) {
          setAuthError(error.message);
        }
      } finally {
        if (active) {
          setAuthChecked(true);
          setLoading(false);
        }
      }
    }

    checkCurrentAdmin();

    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    if (admin) {
      setLoading(true);
      refreshData();
    }
  }, [admin, refreshData]);

  const stats = useMemo(
    () => calculateStats(devices, events),
    [devices, events]
  );
  const canManageDevices = admin?.role === "ADMIN";

  function openAction(device, action) {
    if (!canManageDevices) {
      return;
    }

    setActionState({ device, action });
    setActionReason("");
    setActionError("");
  }

  async function confirmAction() {
    if (!actionState || !canManageDevices) {
      return;
    }

    const { action, device } = actionState;
    const reason = actionReason.trim();

    setActionBusy(true);
    setActionError("");

    try {
      if (action === "suspend") {
        await suspendDevice(device.did, reason);
      } else if (action === "activate") {
        await activateDevice(device.did);
      } else if (action === "revoke") {
        await revokeDevice(device.did, reason);
      }

      setActionState(null);
      setActionReason("");
      await refreshData();
    } catch (error) {
      setActionError(error.message);
    } finally {
      setActionBusy(false);
    }
  }

  async function handleLogin(username, password) {
    setLoginBusy(true);
    setAuthError("");

    try {
      const result = await loginAdmin(username.trim(), password);

      setAdmin(result.data.admin);
    } catch (error) {
      setAuthError(error.message);
    } finally {
      setLoginBusy(false);
    }
  }

  async function handleLogout() {
    try {
      await logoutAdmin();
    } catch {
      // The local dashboard state should clear even if the network drops.
    }

    setAdmin(null);
    setHealth(null);
    setDevices(null);
    setEvents(null);
    setPerformance(null);
    setErrors({});
    setSelectedDevice(null);
    setActionState(null);
    setLastRefreshed(null);
    setLoading(false);
  }

  const ActiveIcon = NAV_ITEMS.find((item) => item.id === activeView)?.icon ||
    Gauge;

  if (!authChecked) {
    return (
      <main className="login-shell">
        <div className="loading-panel auth-loading">
          <RefreshCw size={24} aria-hidden="true" className="spin" />
          <span>Checking administrator session</span>
        </div>
      </main>
    );
  }

  if (!admin) {
    return (
      <LoginView
        busy={loginBusy}
        error={authError}
        onLogin={handleLogin}
      />
    );
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">
            <ShieldCheck size={24} aria-hidden="true" />
          </div>
          <div>
            <strong>Admin Console</strong>
            <span>Blockchain Authentication</span>
          </div>
        </div>

        <nav aria-label="Dashboard sections">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;

            return (
              <button
                key={item.id}
                className={activeView === item.id ? "nav-item active" : "nav-item"}
                onClick={() => setActiveView(item.id)}
                type="button"
              >
                <Icon size={18} aria-hidden="true" />
                {item.label}
              </button>
            );
          })}
        </nav>

        <div className="api-footnote">
          <span>API Base URL</span>
          <strong>{API_BASE_URL}</strong>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div>
            <p className="eyebrow">Administrator Dashboard</p>
            <h1>
              <ActiveIcon size={28} aria-hidden="true" />
              {NAV_ITEMS.find((item) => item.id === activeView)?.label}
            </h1>
          </div>
          <div className="topbar-actions">
            <span className="admin-pill">
              <UserCircle size={16} aria-hidden="true" />
              {admin.username}
              <strong>{admin.role}</strong>
            </span>
            {lastRefreshed ? (
              <span className="last-refresh">
                Last refresh {lastRefreshed.toLocaleTimeString()}
              </span>
            ) : null}
            <button
              className="button"
              onClick={refreshData}
              disabled={refreshing}
              title="Refresh dashboard data"
              type="button"
            >
              <RefreshCw
                size={17}
                aria-hidden="true"
                className={refreshing ? "spin" : ""}
              />
              {refreshing ? "Refreshing" : "Refresh"}
            </button>
            <button
              className="button button-muted"
              onClick={handleLogout}
              title="Sign out"
              type="button"
            >
              <LogOut size={17} aria-hidden="true" />
              Sign out
            </button>
          </div>
        </header>

        {loading ? (
          <div className="loading-panel">
            <RefreshCw size={24} aria-hidden="true" className="spin" />
            <span>Loading dashboard data</span>
          </div>
        ) : null}

        {!loading && activeView === "overview" ? (
          <Overview
            health={health}
            errors={errors}
            stats={stats}
            events={events}
          />
        ) : null}

        {!loading && activeView === "devices" ? (
          <DevicesView
            devices={devices}
            error={errors.devices}
            deviceSearch={deviceSearch}
            setDeviceSearch={setDeviceSearch}
            deviceStatusFilter={deviceStatusFilter}
            setDeviceStatusFilter={setDeviceStatusFilter}
            selectedDevice={selectedDevice}
            setSelectedDevice={setSelectedDevice}
            canManageDevices={canManageDevices}
            onAction={openAction}
          />
        ) : null}

        {!loading && activeView === "audit" ? (
          <AuditView
            events={events}
            error={errors.audit}
            decisionFilter={decisionFilter}
            setDecisionFilter={setDecisionFilter}
            spoofingFilter={spoofingFilter}
            setSpoofingFilter={setSpoofingFilter}
            auditSearch={auditSearch}
            setAuditSearch={setAuditSearch}
          />
        ) : null}

        {!loading && activeView === "alerts" ? (
          <SpoofingAlertsView events={events} error={errors.audit} />
        ) : null}

        {!loading && activeView === "performance" ? (
          <PerformanceView
            performance={performance}
            health={health}
            error={errors.performance}
          />
        ) : null}
      </main>

      <ActionModal
        actionState={actionState}
        reason={actionReason}
        setReason={setActionReason}
        busy={actionBusy}
        error={actionError}
        onCancel={() => setActionState(null)}
        onConfirm={confirmAction}
      />
    </div>
  );
}

export default App;
