/**
 * Analytics aggregation.
 *
 * Every function here derives its output strictly from the session /
 * finding / meta records it is given (either the live API response, or
 * the bundled SAMPLE_* data computed from public/sample-data/sample_traffic.pcap
 * — see sampleAnalysis.js for provenance). Nothing in this file invents,
 * randomizes, or hardcodes a graph value. Where a metric can't be derived
 * from what's actually present, the corresponding field is `null` and the
 * UI is expected to render "N/A" / an empty state instead of a fabricated
 * number.
 */

function timeToSeconds(t) {
  if (!t || typeof t !== "string") return null;
  const parts = t.split(":").map(Number);
  if (parts.length !== 3 || parts.some((n) => Number.isNaN(n))) return null;
  const [h, m, s] = parts;
  return h * 3600 + m * 60 + s;
}

/**
 * Flatten every session's real `timeline` entries into one ordered list of
 * packet-level events. Each timeline entry corresponds to one captured
 * packet/frame. Bytes are only attributed to an event when the owning
 * session has exactly one timeline entry, in which case the session's own
 * (real, parsed) byte_count unambiguously belongs to that single frame.
 * When a session has multiple entries and no per-packet byte breakdown
 * exists in the data, byte_count is left at 0 for each rather than guessed.
 */
function flattenPacketEvents(sessions) {
  const events = [];
  for (const s of sessions) {
    if (!Array.isArray(s.timeline) || s.timeline.length === 0) continue;
    const bytesPerEvent = s.timeline.length === 1 ? (s.byte_count || 0) : 0;
    s.timeline.forEach((t, idx) => {
      events.push({
        time: t.time || null,
        seconds: timeToSeconds(t.time),
        label: t.label,
        sessionId: s.id,
        src_ip: s.src_ip,
        dst_ip: s.dst_ip,
        src_port: s.src_port,
        dst_port: s.dst_port,
        protocol: s.protocol_guess || s.protocol || "Unknown",
        bytes: bytesPerEvent,
      });
    });
  }
  events.sort((a, b) => (a.seconds ?? 0) - (b.seconds ?? 0));
  return events;
}

function buildTrafficOverTime(packetEvents) {
  if (packetEvents.length === 0) return [];
  const buckets = new Map();
  for (const e of packetEvents) {
    const key = e.time || "unknown";
    if (!buckets.has(key)) buckets.set(key, { time: key, packets: 0, bytes: 0, seconds: e.seconds });
    const b = buckets.get(key);
    b.packets += 1;
    b.bytes += e.bytes;
  }
  return Array.from(buckets.values()).sort((a, b) => (a.seconds ?? 0) - (b.seconds ?? 0));
}

function buildProtocolDistribution(sessions) {
  const totalPackets = sessions.reduce((acc, s) => acc + (s.packet_count || 0), 0);
  if (totalPackets === 0) return [];
  const byProtocol = new Map();
  for (const s of sessions) {
    const key = s.protocol_guess || s.protocol || "Unknown";
    const packets = s.packet_count || 0;
    if (!byProtocol.has(key)) byProtocol.set(key, { protocol: key, packets: 0, bytes: 0 });
    const p = byProtocol.get(key);
    p.packets += packets;
    p.bytes += s.byte_count || 0;
  }
  return Array.from(byProtocol.values())
    .map((p) => ({ ...p, pct: totalPackets ? Math.round((p.packets / totalPackets) * 1000) / 10 : 0 }))
    .sort((a, b) => b.packets - a.packets);
}

function buildIpTable(sessions, direction) {
  const key = direction === "src" ? "src_ip" : "dst_ip";
  const byIp = new Map();
  for (const s of sessions) {
    const ip = s[key];
    if (!ip) continue;
    if (!byIp.has(ip)) byIp.set(ip, { ip, packets: 0, bytes: 0, risk: null });
    const row = byIp.get(ip);
    row.packets += s.packet_count || 0;
    row.bytes += s.byte_count || 0;
    // Only surface a risk value when the underlying session actually carries one.
    if (s.risk) row.risk = row.risk && row.risk !== s.risk ? "mixed" : s.risk;
  }
  return Array.from(byIp.values()).sort((a, b) => b.packets - a.packets);
}

function buildPortActivity(sessions) {
  const byPort = new Map();
  for (const s of sessions) {
    const port = s.dst_port;
    if (port === undefined || port === null) continue;
    if (!byPort.has(port)) {
      byPort.set(port, { port, protocol: s.protocol_guess || s.protocol || "Unknown", packets: 0, bytes: 0 });
    }
    const row = byPort.get(port);
    row.packets += s.packet_count || 0;
    row.bytes += s.byte_count || 0;
  }
  return Array.from(byPort.values()).sort((a, b) => a.port - b.port);
}

function buildSessionRows(sessions) {
  return sessions.map((s) => {
    let durationSec = null;
    if (Array.isArray(s.timeline) && s.timeline.length >= 2) {
      const first = timeToSeconds(s.timeline[0].time);
      const last = timeToSeconds(s.timeline[s.timeline.length - 1].time);
      if (first !== null && last !== null) durationSec = Math.max(0, last - first);
    }
    return {
      id: s.id,
      src: s.src_ip && s.src_port !== undefined ? `${s.src_ip}:${s.src_port}` : s.src_ip || "N/A",
      dst: s.dst_ip && s.dst_port !== undefined ? `${s.dst_ip}:${s.dst_port}` : s.dst_ip || "N/A",
      protocol: s.protocol_guess || s.protocol || "Unknown",
      packets: s.packet_count ?? null,
      bytes: s.byte_count ?? null,
      durationSec,
      risk: s.risk || null,
    };
  });
}

function buildTls(sessions, stats) {
  const tlsSessionsSeen = stats?.tls_sessions_seen ?? 0;
  if (!tlsSessionsSeen) {
    return { hasData: false };
  }
  // Only reached once the underlying analysis actually reports TLS
  // sessions — left deliberately unpopulated beyond that flag, since this
  // sample capture never exercises it and inventing version/cipher
  // breakdowns here would violate the "no fake data" requirement.
  return { hasData: true, tlsSessionsSeen };
}

function buildFindingsBySeverity(findings) {
  const order = ["critical", "high", "medium", "low", "info"];
  const counts = new Map();
  for (const f of findings) {
    const sev = (f.severity || "info").toLowerCase();
    counts.set(sev, (counts.get(sev) || 0) + 1);
  }
  return order
    .filter((sev) => counts.has(sev))
    .map((sev) => ({ severity: sev, count: counts.get(sev) }));
}

function buildCommunication(sessions) {
  const nodes = new Map();
  const edges = new Map();
  for (const s of sessions) {
    if (!s.src_ip || !s.dst_ip) continue;
    if (!nodes.has(s.src_ip)) nodes.set(s.src_ip, { ip: s.src_ip, packets: 0 });
    if (!nodes.has(s.dst_ip)) nodes.set(s.dst_ip, { ip: s.dst_ip, packets: 0 });
    nodes.get(s.src_ip).packets += s.packet_count || 0;
    nodes.get(s.dst_ip).packets += s.packet_count || 0;

    const key = `${s.src_ip}->${s.dst_ip}`;
    if (!edges.has(key)) edges.set(key, { from: s.src_ip, to: s.dst_ip, packets: 0, bytes: 0 });
    const e = edges.get(key);
    e.packets += s.packet_count || 0;
    e.bytes += s.byte_count || 0;
  }
  const nodeList = Array.from(nodes.values());
  const edgeList = Array.from(edges.values());
  if (nodeList.length < 2 || edgeList.length === 0) return null;
  return { nodes: nodeList, edges: edgeList };
}

function buildCaptureRows(packetEvents) {
  return packetEvents.map((e, i) => ({
    key: `${e.sessionId}-${i}`,
    timestamp: e.time || "N/A",
    src: e.src_ip ? `${e.src_ip}${e.src_port !== undefined ? ":" + e.src_port : ""}` : "N/A",
    dst: e.dst_ip ? `${e.dst_ip}${e.dst_port !== undefined ? ":" + e.dst_port : ""}` : "N/A",
    protocol: e.protocol,
    srcPort: e.src_port ?? null,
    dstPort: e.dst_port ?? null,
    size: e.bytes,
    session: e.sessionId,
  }));
}

export function buildAnalytics({ sessions, findings, meta, stats }) {
  const safeSessions = Array.isArray(sessions) ? sessions : [];
  const safeFindings = Array.isArray(findings) ? findings : [];

  const packetEvents = flattenPacketEvents(safeSessions);

  const uniqueIps = new Set();
  safeSessions.forEach((s) => {
    if (s.src_ip) uniqueIps.add(s.src_ip);
    if (s.dst_ip) uniqueIps.add(s.dst_ip);
  });

  const totalPackets = meta?.packet_count ?? (safeSessions.reduce((a, s) => a + (s.packet_count || 0), 0) || null);
  const totalBytes = safeSessions.length
    ? safeSessions.reduce((a, s) => a + (s.byte_count || 0), 0)
    : null;

  const protocolDistribution = buildProtocolDistribution(safeSessions);

  return {
    summary: {
      totalPackets,
      totalBytes,
      sessionCount: safeSessions.length || null,
      uniqueIpCount: uniqueIps.size || null,
      protocolCount: protocolDistribution.length || null,
      findingCount: safeFindings.length || null,
    },
    trafficOverTime: buildTrafficOverTime(packetEvents),
    protocolDistribution,
    topSourceIps: buildIpTable(safeSessions, "src"),
    topDestIps: buildIpTable(safeSessions, "dst"),
    portActivity: buildPortActivity(safeSessions),
    sessionRows: buildSessionRows(safeSessions),
    tls: buildTls(safeSessions, stats),
    findingsBySeverity: buildFindingsBySeverity(safeFindings),
    communication: buildCommunication(safeSessions),
    captureRows: buildCaptureRows(packetEvents),
  };
}
