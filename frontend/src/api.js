// Centralized API layer. Every backend call goes through here: credentials
// (the JWT session cookie), JSON handling, and a consistent error shape.
export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

async function request(path, { method = "GET", body, params } = {}) {
  const url = new URL(path, window.location.origin);
  if (params) {
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== "") url.searchParams.set(k, v);
    });
  }
  let res;
  try {
    res = await fetch(url.toString(), {
      method,
      credentials: "include",
      headers: body instanceof FormData ? undefined : { "Content-Type": "application/json" },
      body: body instanceof FormData ? body : body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new ApiError("Network error — is the backend running and reachable?", 0);
  }
  const contentType = res.headers.get("content-type") || "";
  const isJson = contentType.includes("application/json");
  const data = isJson ? await res.json().catch(() => null) : null;
  if (!res.ok) {
    const detail = isJson && data ? data.detail || data.error : null;
    throw new ApiError(typeof detail === "string" ? detail : `Request failed (${res.status})`, res.status);
  }
  return data;
}

export const api = {
  get: (path, params) => request(path, { method: "GET", params }),
  post: (path, body, params) => request(path, { method: "POST", body, params }),
  put: (path, body, params) => request(path, { method: "PUT", body, params }),
};

// --- auth ---
export const authApi = {
  me: () => api.get("/api/auth/me"),
  login: (username, password) => api.post("/api/auth/login", { username, password }),
  register: (username, email, password) => api.post("/api/auth/register", { username, email, password }),
  logout: () => api.post("/api/auth/logout", {}),
  updateMe: (data) => api.put("/api/auth/me", data),
};

// --- investigations ---
export const invApi = {
  get: (id) => api.get(`/api/investigations/${id}`),
  summary: (id) => api.get(`/api/investigations/${id}/summary`),
  loadDemo: () => api.post("/api/demo/load", {}),
  upload: (file, title, onProgress) =>
    new Promise((resolve, reject) => {
      const form = new FormData();
      form.append("file", file);
      const xhr = new XMLHttpRequest();
      xhr.open("POST", `/api/pcaps/upload?title=${encodeURIComponent(title)}`);
      xhr.withCredentials = true;
      xhr.upload.onprogress = (e) => {
        if (e.lengthComputable && onProgress) onProgress(Math.round((e.loaded / e.total) * 100));
      };
      xhr.onload = () => {
        let data;
        try { data = JSON.parse(xhr.responseText); } catch { data = null; }
        if (xhr.status >= 200 && xhr.status < 300) resolve(data);
        else reject(new ApiError((data && (data.detail || data.error)) || `Upload failed (${xhr.status})`, xhr.status));
      };
      xhr.onerror = () => reject(new ApiError("Network error during upload", 0));
      xhr.send(form);
    }),
};

// --- sessions ---
export const sessionsApi = {
  // Paginated: returns { items, total, page, page_size, total_pages } so a
  // large PCAP's session list can be paged through instead of loaded in one go.
  list: (investigationId, page = 1, pageSize = 50) =>
    api.get("/api/sessions", { investigation_id: investigationId, page, page_size: pageSize }),
  get: (id) => api.get(`/api/sessions/${id}`),
  tls: (id) => api.get(`/api/sessions/${id}/tls`),
  certificate: (id) => api.get(`/api/sessions/${id}/certificate`),
  risk: (id) => api.get(`/api/risk/${id}`),
  ai: (id) => api.get(`/api/ai/${id}`),
};

// --- findings ---
export const findingsApi = {
  list: (investigationId) => api.get("/api/findings", { investigation_id: investigationId }),
  get: (id) => api.get(`/api/findings/${id}`),
};

// --- reports ---
export const reportsApi = {
  generate: (investigationId, format) => api.post("/api/reports", {}, { investigation_id: investigationId, format }),
  list: (investigationId) => api.get("/api/reports", { investigation_id: investigationId }),
  downloadUrl: (id) => `/api/reports/${id}`,
};

// --- assistant ---
export const assistantApi = {
  ask: (message, investigationId, sessionId) =>
    api.post("/api/assistant", { message, investigation_id: investigationId, session_id: sessionId }),
};

// --- system ---
export const systemApi = {
  dependencies: () => api.get("/api/system/dependencies"),
  health: () => api.get("/api/health"),
};

// --- threat intelligence ---
export const threatIntelApi = {
  get: (investigationId) => api.get("/api/threat-intel", { investigation_id: investigationId }),
};

// --- tools ---
export const toolsApi = {
  // File-download endpoints: navigated to directly (new tab / anchor),
  // not fetched through the JSON `api` helper.
  downloadPcapUrl: (investigationId) => `/api/investigations/${investigationId}/pcap/download`,
  exportFindingPacketsUrl: (findingId) => `/api/findings/${findingId}/packet-export`,
};
