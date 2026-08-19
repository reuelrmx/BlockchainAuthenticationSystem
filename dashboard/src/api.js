const DEFAULT_API_BASE_URL = "http://localhost:3000";

export const API_BASE_URL = (
  import.meta.env.VITE_API_BASE_URL || DEFAULT_API_BASE_URL
).replace(/\/$/, "");

class ApiError extends Error {
  constructor(message, status, body) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }
}

async function request(path, options = {}) {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {})
    },
    ...options
  });
  let body = null;

  try {
    body = await response.json();
  } catch {
    body = null;
  }

  if (!response.ok) {
    throw new ApiError(
      body?.message || body?.reason || `Request failed with ${response.status}`,
      response.status,
      body
    );
  }

  return body;
}

export function getHealth() {
  return request("/api/health");
}

export function loginAdmin(username, password) {
  return request("/api/admin/login", {
    method: "POST",
    body: JSON.stringify({
      username,
      password
    })
  });
}

export function logoutAdmin() {
  return request("/api/admin/logout", {
    method: "POST"
  });
}

export function getCurrentAdmin() {
  return request("/api/admin/me");
}

export function getDevices() {
  return request("/api/devices");
}

export function getAuthenticationEvents() {
  return request("/api/audit/authentication");
}

export function getPerformanceSummary() {
  return request("/api/performance/summary");
}

export function suspendDevice(did, reason) {
  return request(`/api/devices/${encodeURIComponent(did)}/suspend`, {
    method: "PATCH",
    body: JSON.stringify({ reason })
  });
}

export function activateDevice(did) {
  return request(`/api/devices/${encodeURIComponent(did)}/activate`, {
    method: "PATCH"
  });
}

export function revokeDevice(did, reason) {
  return request(`/api/devices/${encodeURIComponent(did)}/revoke`, {
    method: "PATCH",
    body: JSON.stringify({ reason })
  });
}

export { ApiError };
