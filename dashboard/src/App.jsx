import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  Ban,
  BarChart3,
  Clock3,
  Eye,
  FileText,
  Gauge,
  Lock,
  LogIn,
  LogOut,
  Plus,
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
  registerDevice,
  revokeDevice,
  suspendDevice
} from "./api";

const NAV_ITEMS = [
  {
    id: "overview",
    label: "Overview",
    icon: Gauge,
    description: "Device and authentication summary metrics."
  },
  {
    id: "devices",
    label: "Devices",
    icon: Smartphone,
    description: "Manage registered device identities."
  },
  {
    id: "audit",
    label: "Authentication Audit",
    icon: FileText,
    description: "Immutable authentication outcomes and denial reasons."
  },
  {
    id: "alerts",
    label: "Spoofing Alerts",
    icon: ShieldAlert,
    description: "MAC and IP mismatch events detected during authentication."
  },
  {
    id: "performance",
    label: "Performance",
    icon: BarChart3,
    description: "Authentication response time, success rate, and throughput."
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
const POLLING_INTERVAL_MS = 5000;
const SIDEBAR_WIDTH_STORAGE_KEY = "blockchain-auth-sidebar-width";
const SIDEBAR_DEFAULT_WIDTH = 230;
const SIDEBAR_MIN_WIDTH = 72;
const SIDEBAR_MAX_WIDTH = 320;
const SIDEBAR_COLLAPSED_WIDTH = 96;
const DISPLAY_LABELS = {
  ACTIVE: "Active",
  SUSPENDED: "Suspended",
  REVOKED: "Revoked",
  GRANTED: "Granted",
  DENIED: "Denied",
  VALID_SIGNATURE: "Valid signature",
  INVALID_SIGNATURE: "Invalid signature",
  MAC_MISMATCH: "MAC mismatch",
  IP_MISMATCH: "IP mismatch",
  MAC_AND_IP_MISMATCH: "MAC & IP mismatch",
  MAC_AND_IP_MISMATCH_DETECTED: "MAC & IP mismatch",
  CONTEXT_INCOMPLETE: "Context incomplete",
  NOT_EVALUATED: "Not evaluated",
  NONE: "None",
  PASS: "Pass",
  FAIL: "Fail",
  UNAVAILABLE: "Unavailable",
  UNKNOWN: "Unknown",
  ALL: "All"
};
const AUDIT_REASON_LABELS = {
  VALID_SIGNATURE: "Valid signature",
  INVALID_SIGNATURE: "Invalid signature",
  MAC_MISMATCH: "MAC mismatch",
  IP_MISMATCH: "IP mismatch",
  MAC_AND_IP_MISMATCH: "MAC & IP mismatch",
  MAC_AND_IP_MISMATCH_DETECTED: "MAC & IP mismatch",
  DEVICE_NOT_ACTIVE: "Device is not active",
  INVALID_CHALLENGE: "Invalid or expired authentication challenge",
  CHALLENGE_NOT_FOUND: "Invalid or expired authentication challenge",
  CHALLENGE_EXPIRED: "Invalid or expired authentication challenge",
  CHALLENGE_ALREADY_USED: "Authentication challenge already used",
  DID_MISMATCH: "Challenge does not belong to this DID",
  DEVICE_NOT_FOUND: "Device identity was not found",
  DEVICE_SUSPENDED: "Device is suspended",
  DEVICE_REVOKED: "Device is revoked",
  SIGNATURE_VERIFICATION_FAILED: "Signature verification failed",
  FABRIC_QUERY_FAILED: "Unable to evaluate device identity on Fabric",
  SPOOFING_CONTEXT_INCOMPLETE: "Observed network context is incomplete"
};

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

function formatReason(value) {
  if (!value) {
    return "Not recorded";
  }

  const reason = String(value);
  const normalized = reason.toUpperCase();

  if (AUDIT_REASON_LABELS[normalized]) {
    return AUDIT_REASON_LABELS[normalized];
  }

  return reason
    .replace(/_/g, " ")
    .toLowerCase()
    .replace(/(^|\s)\S/g, (letter) => letter.toUpperCase());
}

function formatDisplayLabel(value) {
  if (!value) {
    return "Not recorded";
  }

  const normalized = String(value).toUpperCase();

  return DISPLAY_LABELS[normalized] || normalized
    .replace(/_/g, " ")
    .toLowerCase()
    .replace(/(^|\s)\S/g, (letter) => letter.toUpperCase());
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

function getTone(value) {
  const normalized = String(value || "UNKNOWN").toUpperCase();

  if (["ACTIVE", "GRANTED", "PASS", "NONE"].includes(normalized)) {
    return "success";
  }

  if ([
    "SUSPENDED",
    "MAC_MISMATCH",
    "IP_MISMATCH",
    "MAC_AND_IP_MISMATCH",
    "MAC_AND_IP_MISMATCH_DETECTED",
    "CONTEXT_INCOMPLETE"
  ].includes(normalized)) {
    return "warning";
  }

  if ([
    "REVOKED",
    "DENIED",
    "FAIL"
  ].includes(normalized)) {
    return "danger";
  }

  return "neutral";
}

function normalizeMacAddress(macAddress) {
  return String(macAddress || "").trim().toUpperCase();
}

function isValidMacAddress(macAddress) {
  return /^([0-9A-F]{2}:){5}[0-9A-F]{2}$/.test(
    normalizeMacAddress(macAddress)
  );
}

function isValidIpv4Address(ipAddress) {
  const parts = String(ipAddress || "").trim().split(".");

  return parts.length === 4 && parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) {
      return false;
    }

    const number = Number(part);

    return number >= 0 && number <= 255;
  });
}

function isValidIpv6Address(ipAddress) {
  const value = String(ipAddress || "").trim();

  if (!value.includes(":") || value.includes(":::")) {
    return false;
  }

  const sections = value.split(":");
  const compressed = value.includes("::");

  if (compressed) {
    if (value.indexOf("::") !== value.lastIndexOf("::")) {
      return false;
    }

    return sections.length <= 8 && sections.every((section) =>
      section === "" || /^[0-9A-Fa-f]{1,4}$/.test(section)
    );
  }

  return sections.length === 8 && sections.every((section) =>
    /^[0-9A-Fa-f]{1,4}$/.test(section)
  );
}

function isValidIpAddress(ipAddress) {
  return isValidIpv4Address(ipAddress) || isValidIpv6Address(ipAddress);
}

function isValidPublicKeyPem(publicKey) {
  const value = String(publicKey || "").trim();

  return (
    value.includes("-----BEGIN PUBLIC KEY-----") &&
    value.includes("-----END PUBLIC KEY-----") &&
    !value.includes("PRIVATE KEY")
  );
}

function clampSidebarWidth(width) {
  const numericWidth = Number(width);

  if (!Number.isFinite(numericWidth)) {
    return SIDEBAR_DEFAULT_WIDTH;
  }

  return Math.min(
    SIDEBAR_MAX_WIDTH,
    Math.max(SIDEBAR_MIN_WIDTH, numericWidth)
  );
}

function readStoredSidebarWidth() {
  if (typeof window === "undefined") {
    return SIDEBAR_DEFAULT_WIDTH;
  }

  try {
    const storedWidth = window.localStorage.getItem(
      SIDEBAR_WIDTH_STORAGE_KEY
    );

    return clampSidebarWidth(storedWidth || SIDEBAR_DEFAULT_WIDTH);
  } catch {
    return SIDEBAR_DEFAULT_WIDTH;
  }
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

function StatCard({ label, value, detail, tone = "neutral" }) {
  return (
    <section className={`stat-card tone-${tone}`}>
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

function StatusIndicator({ value, className = "" }) {
  const normalized = String(value || "UNKNOWN").toUpperCase();
  const label = formatDisplayLabel(normalized);
  const tone = getTone(normalized);

  return (
    <span className={`status-indicator tone-${tone} ${className}`}>
      <span aria-hidden="true" />
      {label}
    </span>
  );
}

function DecisionBadge({ value }) {
  return (
    <StatusIndicator value={value} />
  );
}

function SpoofingBadge({ value }) {
  return <StatusIndicator value={value} />;
}

function RequirementBadge({ value }) {
  const normalized = value === null || value === undefined
    ? "UNAVAILABLE"
    : value ? "PASS" : "FAIL";

  return <StatusIndicator value={normalized} />;
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
            {formatDisplayLabel(option)}
          </option>
        ))}
      </select>
    </label>
  );
}

function SearchBox({ value, onChange, placeholder }) {
  return (
    <label className="search-box">
      <span>Search</span>
      <span className="search-input-wrap">
        <Search size={17} aria-hidden="true" />
        <input
          value={value}
          onChange={(event) => onChange(event.target.value)}
          placeholder={placeholder}
          type="search"
        />
      </span>
    </label>
  );
}

function PageSection({ title, description, toolbar, children }) {
  const hasHeadingText = Boolean(title || description);

  return (
    <section className="page-section">
      {(title || description || toolbar) ? (
        <div
          className={hasHeadingText
            ? "section-header"
            : "section-header toolbar-only"}
        >
          <div>
            {title ? <h2>{title}</h2> : null}
            {description ? <p>{description}</p> : null}
          </div>
          {toolbar ? <div className="section-toolbar">{toolbar}</div> : null}
        </div>
      ) : null}
      {children}
    </section>
  );
}

function Overview({ stats }) {
  return (
    <div className="view-stack">
      <div className="stat-grid">
        <StatCard
          label="Total Devices"
          value={stats.totalDevices}
          detail="Registered identities"
        />
        <StatCard
          label="Active Devices"
          value={stats.activeDevices}
          tone="success"
        />
        <StatCard
          label="Suspended Devices"
          value={stats.suspendedDevices}
          tone="warning"
        />
        <StatCard
          label="Revoked Devices"
          value={stats.revokedDevices}
          tone="danger"
        />
        <StatCard
          label="Authentication Events"
          value={stats.totalEvents}
          detail={
            stats.successRate === null
              ? "Success rate unavailable"
              : `${stats.successRate}% success rate`
          }
        />
        <StatCard
          label="Granted"
          value={stats.grantedAttempts}
          tone="success"
        />
        <StatCard
          label="Denied"
          value={stats.deniedAttempts}
          tone="warning"
        />
        <StatCard
          label="Spoofing Incidents"
          value={stats.spoofingIncidents}
          tone="danger"
        />
      </div>
    </div>
  );
}

function DeviceActions({ device, onAction, canManage }) {
  const status = getDeviceStatus(device);

  if (!canManage || status === "REVOKED") {
    return null;
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
  setSelectedDevice
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
      <PageSection
        toolbar={
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
        }
      >
        {error ? <ErrorState message={error} /> : null}
        {!error && devices && filteredDevices.length === 0 ? (
          <EmptyState message="No devices match the current filters." />
        ) : null}
        {!error && devices ? (
          <div className="table-wrap">
            <table className="device-table">
              <colgroup>
                <col className="col-did" />
                <col className="col-owner" />
                <col className="col-ip" />
                <col className="col-mac" />
                <col className="col-status" />
                <col className="col-actions" />
              </colgroup>
              <thead>
                <tr>
                  <th>DID</th>
                  <th>Owner</th>
                  <th>IP Address</th>
                  <th>MAC Address</th>
                  <th>Status</th>
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
                    <td className="mono-cell">
                      {valueOrDash(device.registeredIpAddress)}
                    </td>
                    <td className="mono-cell">
                      {valueOrDash(device.registeredMacAddress)}
                    </td>
                    <td>
                      <StatusIndicator value={device.status} />
                    </td>
                    <td>
                      <div className="row-actions">
                        <button
                          className="icon-button"
                          onClick={() => setSelectedDevice(device)}
                          title="View"
                          type="button"
                        >
                          <Eye size={17} aria-hidden="true" />
                          <span className="sr-only">View</span>
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </PageSection>
    </div>
  );
}

function DetailSection({ title, children }) {
  return (
    <section className="detail-section">
      <h3>{title}</h3>
      <div className="detail-grid">{children}</div>
    </section>
  );
}

function DetailItem({ label, value, mono = false }) {
  return (
    <div className="detail-item">
      <span>{label}</span>
      <strong className={mono ? "detail-value mono-cell" : "detail-value"}>
        {valueOrDash(value)}
      </strong>
    </div>
  );
}

function DeviceDetailsDrawer({ device, onClose, canManageDevices, onAction }) {
  const showLifecycleActions = Boolean(
    device &&
    canManageDevices &&
    getDeviceStatus(device) !== "REVOKED"
  );

  useEffect(() => {
    if (!device) {
      return undefined;
    }

    function handleKeyDown(event) {
      if (event.key === "Escape") {
        onClose();
      }
    }

    document.addEventListener("keydown", handleKeyDown);

    return () => {
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [device, onClose]);

  if (!device) {
    return null;
  }

  return (
    <div
      className="drawer-backdrop"
      onClick={onClose}
      role="presentation"
    >
      <aside
        aria-label="Device Details"
        className="details-drawer"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="drawer-heading">
          <div>
            <p className="eyebrow">Device Details</p>
            <h2>{shortId(device.did)}</h2>
            <p>{device.owner || "Registered device identity"}</p>
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
        <div className="drawer-body">
          <DetailSection title="Identity">
            <DetailItem label="DID" value={device.did} mono />
            <DetailItem label="Owner" value={device.owner} />
            <DetailItem
              label="Status"
              value={<StatusIndicator value={device.status} />}
            />
          </DetailSection>
          <DetailSection title="Network">
            <DetailItem
              label="IP Address"
              value={device.registeredIpAddress}
              mono
            />
            <DetailItem
              label="MAC Address"
              value={device.registeredMacAddress}
              mono
            />
          </DetailSection>
          <DetailSection title="Blockchain Metadata">
            <DetailItem
              label="Registered At"
              value={formatDate(device.registeredAt)}
            />
            <DetailItem label="Updated At" value={formatDate(device.updatedAt)} />
            <DetailItem label="Revoked At" value={formatDate(device.revokedAt)} />
            <DetailItem
              label="Revocation Reason"
              value={device.revocationReason}
            />
            <DetailItem
              label="Suspension Reason"
              value={device.suspensionReason}
            />
            <DetailItem label="Transaction ID" value={device.transactionId} mono />
            <DetailItem
              label="Last Transaction ID"
              value={device.lastTransactionId}
              mono
            />
          </DetailSection>
          <details className="drawer-code-section">
            <summary>Public Key</summary>
            <pre>{valueOrDash(device.publicKey)}</pre>
          </details>
        </div>
        {showLifecycleActions ? (
          <div className="drawer-actions">
            <DeviceActions
              device={device}
              onAction={onAction}
              canManage={canManageDevices}
            />
          </div>
        ) : null}
      </aside>
    </div>
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
    <PageSection
      toolbar={
        <AuditFilters
          decisionFilter={decisionFilter}
          setDecisionFilter={setDecisionFilter}
          spoofingFilter={spoofingFilter}
          setSpoofingFilter={setSpoofingFilter}
          auditSearch={auditSearch}
          setAuditSearch={setAuditSearch}
        />
      }
    >
      {error ? <ErrorState message={error} /> : null}
      {!error && events && filteredEvents.length === 0 ? (
        <EmptyState message="No audit events match the current filters." />
      ) : null}
      {!error && events ? <AuditTable events={filteredEvents} /> : null}
    </PageSection>
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
              <td title={formatReason(event.reason)}>{formatReason(event.reason)}</td>
              <td className="mono-cell">{valueOrDash(event.observedMacAddress)}</td>
              <td className="mono-cell">{valueOrDash(event.observedIpAddress)}</td>
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

function SpoofingAlertsTable({ events }) {
  return (
    <div className="table-wrap">
      <table className="alerts-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Device</th>
            <th>Detection</th>
            <th>Observed IP</th>
            <th>Observed MAC</th>
            <th>Outcome</th>
            <th>Transaction</th>
          </tr>
        </thead>
        <tbody>
          {events.map((event) => (
            <tr key={event.eventId}>
              <td>{formatDate(event.timestamp)}</td>
              <td className="mono-cell" title={event.did}>
                {shortId(event.did)}
              </td>
              <td>
                <SpoofingBadge value={event.spoofingClassification} />
              </td>
              <td className="mono-cell">{valueOrDash(event.observedIpAddress)}</td>
              <td className="mono-cell">{valueOrDash(event.observedMacAddress)}</td>
              <td>
                <DecisionBadge value={event.decision} />
              </td>
              <td className="mono-cell" title={event.transactionId}>
                {valueOrDash(shortId(event.transactionId))}
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
    <PageSection>
      {error ? <ErrorState message={error} /> : null}
      {!error && events && alerts.length === 0 ? (
        <EmptyState message="No confirmed spoofing incidents returned." />
      ) : null}
      {!error && events && alerts.length > 0 ? (
        <SpoofingAlertsTable events={alerts} />
      ) : null}
    </PageSection>
  );
}

function PerformanceTable({ results }) {
  const rows = ["1", "10", "25", "50"]
    .map((level) => ({
      level,
      result: results?.[level] || null
    }));

  if (!results || Object.keys(results).length === 0) {
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
            <th>P95 Latency</th>
            <th>Throughput</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(({ level, result }) => (
            <tr key={level}>
              <td>{level}</td>
              <td>{formatPercent(result?.successRatePercent)}</td>
              <td>{formatMs(result?.meanLatencyMs)}</td>
              <td>{formatMs(result?.p95LatencyMs)}</td>
              <td>
                {formatMetric(result?.throughputPerSecond, " auth/s")}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function PerformanceView({ performance, error }) {
  const formal = performance?.formal || {};
  const level50 = formal.results?.["50"] || null;
  const requirementStatus = formal.requirementStatus || {};
  const hasFormalLevel50 = Boolean(formal.available && level50);

  return (
    <div className="view-stack">
      {error ? <ErrorState message={error} /> : null}
      {formal.evaluationDate ? (
        <p className="performance-meta">
          Last evaluated: {formatDate(formal.evaluationDate)}
        </p>
      ) : null}

      <PageSection title="Summary Metrics">
        {hasFormalLevel50 ? (
          <div className="stat-grid performance-summary-grid">
            <StatCard
              label="Authentication Response Time"
              value={formatMs(level50.meanLatencyMs)}
              detail="50-concurrent mean latency"
            />
            <StatCard
              label="Authentication Success Rate"
              value={formatPercent(level50.successRatePercent)}
              detail="50-concurrent result"
              tone="success"
            />
            <StatCard
              label="Observed Authentication Throughput"
              value={formatMetric(level50.throughputPerSecond, " auth/s")}
              detail="50-concurrent measured throughput"
            />
            <StatCard
              label="Spoofing Detection Time"
              value={formatMs(level50.spoofingCheckDurationMs?.mean)}
              detail="50-concurrent mean spoofing check"
            />
          </div>
        ) : (
          <EmptyState message={formal.message || "No evaluation data available."} />
        )}
      </PageSection>

      <PageSection
        title="Requirements"
      >
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
              <span>50 concurrent authentication requests</span>
              <RequirementBadge value={requirementStatus.fiftyConcurrent} />
            </div>
            <div className="requirement-item">
              <span>Spoofing detection &lt;= 3 s</span>
              <RequirementBadge value={requirementStatus.spoofingUnder3Seconds} />
            </div>
          </div>
        )}
      </PageSection>

      <PageSection
        title="Concurrency Results"
      >
        {!formal.available ? (
          <EmptyState message={formal.message || "No evaluation data available."} />
        ) : (
          <PerformanceTable results={formal.results} />
        )}
      </PageSection>

    </div>
  );
}

function AddDeviceModal({ open, onClose, onRegister }) {
  const [owner, setOwner] = useState("");
  const [macAddress, setMacAddress] = useState("");
  const [ipAddress, setIpAddress] = useState("");
  const [publicKey, setPublicKey] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [registeredDevice, setRegisteredDevice] = useState(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (open) {
      setOwner("");
      setMacAddress("");
      setIpAddress("");
      setPublicKey("");
      setError("");
      setBusy(false);
      setRegisteredDevice(null);
      setCopied(false);
    }
  }, [open]);

  useEffect(() => {
    if (!open) {
      return undefined;
    }

    function handleKeyDown(event) {
      if (event.key === "Escape") {
        onClose();
      }
    }

    document.addEventListener("keydown", handleKeyDown);

    return () => {
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [onClose, open]);

  if (!open) {
    return null;
  }

  function validateRegistration() {
    const trimmedOwner = owner.trim();
    const normalizedMacAddress = normalizeMacAddress(macAddress);
    const trimmedIpAddress = ipAddress.trim();
    const trimmedPublicKey = publicKey.trim();

    if (!trimmedOwner) {
      throw new Error("Owner / device name is required");
    }

    if (!isValidMacAddress(normalizedMacAddress)) {
      throw new Error("MAC address must use AA:BB:CC:DD:EE:FF format");
    }

    if (!isValidIpAddress(trimmedIpAddress)) {
      throw new Error("IP address is not valid");
    }

    if (!isValidPublicKeyPem(trimmedPublicKey)) {
      throw new Error("Public key must be a PEM public key");
    }

    return {
      owner: trimmedOwner,
      macAddress: normalizedMacAddress,
      ipAddress: trimmedIpAddress,
      publicKey: trimmedPublicKey
    };
  }

  async function handlePublicKeyFile(event) {
    const file = event.target.files?.[0];

    setError("");

    if (!file) {
      return;
    }

    if (file.name.toLowerCase().includes("private")) {
      setError("Select public-key.pem, not a private key file");
      event.target.value = "";
      return;
    }

    try {
      const text = await file.text();

      if (text.includes("PRIVATE KEY")) {
        setError("Private keys are not accepted by the dashboard");
        event.target.value = "";
        return;
      }

      setPublicKey(text.trim());
    } catch (readError) {
      setError(`Unable to read public key file: ${readError.message}`);
    }
  }

  async function handleSubmit(event) {
    event.preventDefault();
    setError("");
    setCopied(false);

    let registration;

    try {
      registration = validateRegistration();
    } catch (validationError) {
      setError(validationError.message);
      return;
    }

    setBusy(true);

    try {
      const device = await onRegister(registration);

      setRegisteredDevice(device);
    } catch (submitError) {
      setError(submitError.message);
    } finally {
      setBusy(false);
    }
  }

  async function copyDid() {
    if (!registeredDevice?.did || !navigator.clipboard) {
      return;
    }

    try {
      await navigator.clipboard.writeText(registeredDevice.did);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  return (
    <div
      className="modal-backdrop"
      onClick={onClose}
      role="presentation"
    >
      <section
        aria-labelledby="add-device-title"
        className="modal add-device-modal"
        onClick={(event) => event.stopPropagation()}
        role="dialog"
      >
        <div className="modal-heading">
          <div>
            <h2 id="add-device-title">Add Device</h2>
            <p>Register an existing device public key on Fabric.</p>
          </div>
          <button
            className="icon-button"
            onClick={onClose}
            title="Close dialog"
            type="button"
          >
            <X size={18} aria-hidden="true" />
            <span className="sr-only">Close dialog</span>
          </button>
        </div>

        {registeredDevice ? (
          <div className="registration-success">
            <StatusIndicator value="ACTIVE" />
            <h3>Device registered successfully</h3>
            <div className="copy-row">
              <code>{registeredDevice.did}</code>
              <button
                className="button button-muted"
                onClick={copyDid}
                type="button"
              >
                {copied ? "Copied" : "Copy DID"}
              </button>
            </div>
          </div>
        ) : (
          <form className="add-device-form" onSubmit={handleSubmit}>
            <label className="login-field">
              <span>Owner / device name</span>
              <input
                autoComplete="off"
                onChange={(event) => setOwner(event.target.value)}
                required
                type="text"
                value={owner}
              />
            </label>

            <div className="form-grid">
              <label className="login-field">
                <span>MAC address</span>
                <input
                  autoComplete="off"
                  onChange={(event) => setMacAddress(event.target.value)}
                  placeholder="AA:BB:CC:DD:EE:FF"
                  required
                  type="text"
                  value={macAddress}
                />
              </label>

              <label className="login-field">
                <span>IP address</span>
                <input
                  autoComplete="off"
                  onChange={(event) => setIpAddress(event.target.value)}
                  placeholder="192.168.1.10"
                  required
                  type="text"
                  value={ipAddress}
                />
              </label>
            </div>

            <label className="login-field">
              <span>Load public-key.pem</span>
              <input
                accept=".pem,.pub,text/plain"
                onChange={handlePublicKeyFile}
                type="file"
              />
            </label>

            <label className="reason-field add-public-key-field">
              <span>Public key</span>
              <textarea
                onChange={(event) => setPublicKey(event.target.value)}
                placeholder="-----BEGIN PUBLIC KEY-----"
                required
                rows={8}
                value={publicKey}
              />
            </label>

            {error ? <ErrorState message={error} /> : null}

            <div className="modal-actions">
              <button
                className="button button-muted"
                disabled={busy}
                onClick={onClose}
                type="button"
              >
                Cancel
              </button>
              <button
                className="button"
                disabled={busy}
                type="submit"
              >
                {busy ? "Registering" : "Register Device"}
              </button>
            </div>
          </form>
        )}
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
            <p className="eyebrow">Administrator Console</p>
            <h1>Blockchain Authentication</h1>
            <p className="login-subtitle">Secure administrative access</p>
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
      </form>
    </main>
  );
}

function isUnauthorizedResult(result) {
  return result.status === "rejected" && result.reason?.status === 401;
}

async function settleRequest(requester) {
  try {
    return {
      status: "fulfilled",
      value: await requester()
    };
  } catch (reason) {
    return {
      status: "rejected",
      reason
    };
  }
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
  const [addDeviceOpen, setAddDeviceOpen] = useState(false);
  const [actionState, setActionState] = useState(null);
  const [actionReason, setActionReason] = useState("");
  const [actionError, setActionError] = useState("");
  const [actionBusy, setActionBusy] = useState(false);
  const [sidebarWidth, setSidebarWidth] = useState(readStoredSidebarWidth);
  const [sidebarResizing, setSidebarResizing] = useState(false);
  const refreshPromiseRef = useRef(null);

  const refreshData = useCallback(async () => {
    if (refreshPromiseRef.current) {
      return refreshPromiseRef.current;
    }

    const refreshPromise = (async () => {
      setRefreshing(true);
      setErrors({});

      const healthResult = await settleRequest(getHealth);
      const devicesResult = await settleRequest(getDevices);
      const auditResult = await settleRequest(getAuthenticationEvents);
      const performanceResult = await settleRequest(getPerformanceSummary);
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
        setAddDeviceOpen(false);
        setLoading(false);
        setRefreshing(false);
        return false;
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

          return deviceData.find((device) => device.did === current.did) ||
            current;
        });
      } else {
        nextErrors.devices = devicesResult.reason.message;
      }

      if (auditResult.status === "fulfilled") {
        setEvents(auditResult.value.data || []);
      } else {
        nextErrors.audit = auditResult.reason.message;
      }

      if (performanceResult.status === "fulfilled") {
        setPerformance(performanceResult.value.data || null);
      } else {
        nextErrors.performance = performanceResult.reason.message;
      }

      setErrors(nextErrors);
      setLastRefreshed(new Date());
      setLoading(false);
      setRefreshing(false);
      return true;
    })();

    refreshPromiseRef.current = refreshPromise;

    try {
      return await refreshPromise;
    } finally {
      refreshPromiseRef.current = null;
    }
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

  useEffect(() => {
    if (!admin) {
      return undefined;
    }

    let stopped = false;
    let timerId = null;

    function scheduleNextRefresh() {
      timerId = window.setTimeout(async () => {
        if (stopped) {
          return;
        }

        if (document.visibilityState === "visible") {
          await refreshData();
        }

        scheduleNextRefresh();
      }, POLLING_INTERVAL_MS);
    }

    function handleVisibilityChange() {
      if (document.visibilityState === "visible") {
        refreshData();
      }
    }

    document.addEventListener("visibilitychange", handleVisibilityChange);
    scheduleNextRefresh();

    return () => {
      stopped = true;

      if (timerId) {
        window.clearTimeout(timerId);
      }

      document.removeEventListener(
        "visibilitychange",
        handleVisibilityChange
      );
    };
  }, [admin, refreshData]);

  useEffect(() => {
    try {
      window.localStorage.setItem(
        SIDEBAR_WIDTH_STORAGE_KEY,
        String(sidebarWidth)
      );
    } catch {
      // Sidebar resizing is optional; storage failures should not affect use.
    }
  }, [sidebarWidth]);

  const stats = useMemo(
    () => calculateStats(devices, events),
    [devices, events]
  );
  const canManageDevices = admin?.role === "ADMIN";
  const sidebarCollapsed = sidebarWidth <= SIDEBAR_COLLAPSED_WIDTH;
  const appShellClassName = [
    "app-shell",
    sidebarCollapsed ? "sidebar-collapsed" : "",
    sidebarResizing ? "sidebar-resizing" : ""
  ].filter(Boolean).join(" ");

  const handleSidebarResizeStart = useCallback((event) => {
    if (window.innerWidth <= 1180) {
      return;
    }

    event.preventDefault();
    setSidebarResizing(true);

    const startX = event.clientX;
    const startWidth = sidebarWidth;

    function handlePointerMove(moveEvent) {
      setSidebarWidth(
        clampSidebarWidth(startWidth + moveEvent.clientX - startX)
      );
    }

    function stopResizing() {
      setSidebarResizing(false);
      window.removeEventListener("pointermove", handlePointerMove);
      window.removeEventListener("pointerup", stopResizing);
      window.removeEventListener("pointercancel", stopResizing);
    }

    window.addEventListener("pointermove", handlePointerMove);
    window.addEventListener("pointerup", stopResizing);
    window.addEventListener("pointercancel", stopResizing);
  }, [sidebarWidth]);

  function openAction(device, action) {
    if (!canManageDevices) {
      return;
    }

    setActionState({ device, action });
    setActionReason("");
    setActionError("");
  }

  async function handleRegisterDevice(registration) {
    if (!canManageDevices) {
      throw new Error("Administrator role is required to register devices");
    }

    const result = await registerDevice(registration);
    const device = result.data;

    await refreshData();

    return device;
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
    setAddDeviceOpen(false);
    setActionState(null);
    setLastRefreshed(null);
    setLoading(false);
    setRefreshing(false);
  }

  const activeNavItem = NAV_ITEMS.find((item) => item.id === activeView) ||
    NAV_ITEMS[0];
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
    <div
      className={appShellClassName}
      style={{ "--sidebar-width": `${sidebarWidth}px` }}
    >
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">
            <ShieldCheck size={24} aria-hidden="true" />
          </div>
          <div className="brand-copy">
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
                onClick={() => {
                  setActiveView(item.id);
                  setSelectedDevice(null);
                }}
                title={item.label}
                type="button"
              >
                <Icon size={18} aria-hidden="true" />
                <span className="nav-label">{item.label}</span>
              </button>
            );
          })}
        </nav>

        <div className="api-footnote">
          <span>API Base URL</span>
          <strong>{API_BASE_URL}</strong>
        </div>
        <button
          aria-label="Resize navigation sidebar"
          className="sidebar-resize-handle"
          onPointerDown={handleSidebarResizeStart}
          title="Drag to resize navigation sidebar"
          type="button"
        />
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div>
            <p className="eyebrow">Administrator Dashboard</p>
            <h1>{activeNavItem.label}</h1>
            <p className="topbar-description">{activeNavItem.description}</p>
          </div>
          <div className="topbar-actions">
            {activeView === "devices" && canManageDevices ? (
              <button
                className="button"
                onClick={() => setAddDeviceOpen(true)}
                title="Register a device public key"
                type="button"
              >
                <Plus size={16} aria-hidden="true" />
                Add device
              </button>
            ) : null}
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
            stats={stats}
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
            setSelectedDevice={setSelectedDevice}
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
      <AddDeviceModal
        open={addDeviceOpen}
        onClose={() => setAddDeviceOpen(false)}
        onRegister={handleRegisterDevice}
      />
      <DeviceDetailsDrawer
        device={selectedDevice}
        onClose={() => setSelectedDevice(null)}
        canManageDevices={canManageDevices}
        onAction={openAction}
      />
    </div>
  );
}

export default App;
