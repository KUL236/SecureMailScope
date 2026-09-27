import { useState } from "react";

/**
 * Small, dependency-free SVG chart primitives for the Analytics page.
 * No charting library is added to the project — these read real,
 * already-aggregated numbers (see analytics.js) and never fabricate
 * data points of their own. Only the visual presentation below has
 * changed; every value plotted still comes straight from the capture.
 */

const SERIES_COLORS = ["var(--accent)", "var(--blue)", "var(--violet)", "var(--amber)", "var(--red)", "var(--green)"];

function smoothPath(pts) {
  // Catmull-Rom -> cubic Bezier, so a handful of real points reads as a
  // clean curve instead of a jagged connect-the-dots line.
  if (pts.length < 3) return `M ${pts.map((p) => `${p.x} ${p.y}`).join(" L ")}`;
  let d = `M ${pts[0].x} ${pts[0].y}`;
  for (let i = 0; i < pts.length - 1; i++) {
    const p0 = pts[i - 1] || pts[i];
    const p1 = pts[i];
    const p2 = pts[i + 1];
    const p3 = pts[i + 2] || p2;
    const c1x = p1.x + (p2.x - p0.x) / 6;
    const c1y = p1.y + (p2.y - p0.y) / 6;
    const c2x = p2.x - (p3.x - p1.x) / 6;
    const c2y = p2.y - (p3.y - p1.y) / 6;
    d += ` C ${c1x} ${c1y} ${c2x} ${c2y} ${p2.x} ${p2.y}`;
  }
  return d;
}

export function BarLineChart({ points, valueKey = "packets", height = 240 }) {
  const [hover, setHover] = useState(null);
  if (!points || points.length === 0) return null;

  const w = 680;
  const padL = 46, padR = 16, padT = 20, padB = 34;
  const innerW = w - padL - padR;
  const innerH = height - padT - padB;
  const max = Math.max(1, ...points.map((p) => p[valueKey] || 0));

  // Enough real timestamps to read as a trend -> smooth area/line.
  // A handful of points stays as discrete bars so nothing is implied
  // between samples that aren't actually there.
  const useLine = points.length > 6;
  const unit = valueKey === "bytes" ? "B" : "pkt";

  const xFor = (i) => padL + (points.length === 1 ? innerW / 2 : (innerW / (points.length - 1)) * i);
  const yFor = (v) => padT + innerH - (max ? (v / max) * innerH : 0);

  const gridFracs = [0, 0.25, 0.5, 0.75, 1];

  return (
    <div className="chart-shell">
      <svg viewBox={`0 0 ${w} ${height}`} width="100%" style={{ maxHeight: height, display: "block", overflow: "visible" }}>
        <defs>
          <linearGradient id="trafficFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--accent)" stopOpacity="0.35" />
            <stop offset="100%" stopColor="var(--accent)" stopOpacity="0" />
          </linearGradient>
        </defs>

        {gridFracs.map((f) => (
          <line
            key={f}
            x1={padL} x2={w - padR}
            y1={padT + innerH * (1 - f)} y2={padT + innerH * (1 - f)}
            stroke="var(--border-soft)" strokeWidth="1" strokeDasharray={f === 0 ? "0" : "3 4"}
          />
        ))}
        {gridFracs.map((f) => (
          <text key={f} x={padL - 10} y={padT + innerH * (1 - f) + 4} textAnchor="end" fontSize="10.5" fill="var(--text-faint)" fontFamily="var(--mono)">
            {Math.round(max * f)}
          </text>
        ))}

        {useLine ? (
          <>
            <path
              d={`${smoothPath(points.map((p, i) => ({ x: xFor(i), y: yFor(p[valueKey] || 0) })))} L ${xFor(points.length - 1)} ${padT + innerH} L ${xFor(0)} ${padT + innerH} Z`}
              fill="url(#trafficFill)" stroke="none"
            />
            <path
              d={smoothPath(points.map((p, i) => ({ x: xFor(i), y: yFor(p[valueKey] || 0) })))}
              fill="none" stroke="var(--accent)" strokeWidth="2.25" strokeLinecap="round" strokeLinejoin="round"
            />
            {points.map((p, i) => (
              <g key={p.time || i}>
                <circle
                  cx={xFor(i)} cy={yFor(p[valueKey] || 0)} r={hover === i ? 5 : 3}
                  fill={hover === i ? "var(--accent)" : "var(--surface)"} stroke="var(--accent)" strokeWidth="1.6"
                  style={{ cursor: "pointer", transition: "r .12s ease" }}
                  onMouseEnter={() => setHover(i)} onMouseLeave={() => setHover(null)}
                />
                <rect x={xFor(i) - 10} y={padT} width="20" height={innerH} fill="transparent"
                  onMouseEnter={() => setHover(i)} onMouseLeave={() => setHover(null)} style={{ cursor: "pointer" }} />
                {(i % Math.ceil(points.length / 8 || 1) === 0 || i === points.length - 1) && (
                  <text x={xFor(i)} y={padT + innerH + 20} textAnchor="middle" fontSize="10" fill="var(--text-faint)" fontFamily="var(--mono)">
                    {p.time}
                  </text>
                )}
              </g>
            ))}
          </>
        ) : (
          <>
            {points.map((p, i) => {
              const barW = Math.min(46, innerW / points.length - 14);
              const x = xFor(i) - barW / 2;
              const val = p[valueKey] || 0;
              const barH = max ? (val / max) * innerH : 0;
              const y = padT + innerH - barH;
              return (
                <g key={p.time || i}
                   onMouseEnter={() => setHover(i)} onMouseLeave={() => setHover(null)}
                   style={{ cursor: "pointer" }}>
                  <rect x={x} y={y} width={barW} height={Math.max(barH, val > 0 ? 3 : 0)} rx="4"
                    fill="var(--accent)" opacity={hover === null || hover === i ? 0.9 : 0.5} />
                  <text x={xFor(i)} y={padT + innerH + 20} textAnchor="middle" fontSize="10" fill="var(--text-faint)" fontFamily="var(--mono)">
                    {p.time}
                  </text>
                </g>
              );
            })}
          </>
        )}
      </svg>

      {hover !== null && points[hover] && (
        <div className="chart-tooltip" style={{ left: `${(xFor(hover) / w) * 100}%` }}>
          <b>{points[hover].time}</b>
          <span>{points[hover][valueKey] ?? 0} {unit}</span>
        </div>
      )}
    </div>
  );
}

export function DonutChart({ slices, size = 176, thickness = 24 }) {
  const [hover, setHover] = useState(null);
  if (!slices || slices.length === 0) return null;
  const total = slices.reduce((a, s) => a + s.value, 0);
  if (total === 0) return null;
  const r = size / 2 - thickness / 2;
  const cx = size / 2, cy = size / 2;
  let angle = -90;
  const gapDeg = slices.length > 1 ? 2.2 : 0;

  const arcs = slices.map((s, i) => {
    const frac = s.value / total;
    const startAngle = angle + gapDeg / 2;
    const endAngle = angle + frac * 360 - gapDeg / 2;
    angle += frac * 360;
    const large = endAngle - startAngle > 180 ? 1 : 0;
    const toRad = (a) => (a * Math.PI) / 180;
    const x1 = cx + r * Math.cos(toRad(startAngle));
    const y1 = cy + r * Math.sin(toRad(startAngle));
    const x2 = cx + r * Math.cos(toRad(endAngle));
    const y2 = cy + r * Math.sin(toRad(endAngle));
    return {
      d: endAngle > startAngle ? `M ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2}` : null,
      color: SERIES_COLORS[i % SERIES_COLORS.length],
      label: s.label, value: s.value, pct: Math.round((frac * 1000)) / 10,
    };
  });

  return (
    <div className="donut-row">
      <svg viewBox={`0 0 ${size} ${size}`} width={size} height={size}>
        {arcs.map((a, i) => a.d && (
          <path
            key={a.label}
            d={a.d}
            fill="none"
            stroke={a.color}
            strokeWidth={thickness}
            strokeLinecap="round"
            opacity={hover === null || hover === i ? 1 : 0.3}
            style={{ transition: "opacity .12s ease", cursor: "pointer" }}
            onMouseEnter={() => setHover(i)}
            onMouseLeave={() => setHover(null)}
          />
        ))}
        <text x={cx} y={cy - 3} textAnchor="middle" fontSize="21" fontWeight="800" fill="var(--text-strong)">
          {hover !== null ? arcs[hover].value : total}
        </text>
        <text x={cx} y={cy + 16} textAnchor="middle" fontSize="9.5" fill="var(--text-faint)" letterSpacing="0.3">
          {hover !== null ? arcs[hover].label : "TOTAL"}
        </text>
      </svg>
      <div className="donut-legend">
        {arcs.map((a, i) => (
          <div key={a.label} className="donut-legend-row" style={{ opacity: hover === null || hover === i ? 1 : 0.5 }}
               onMouseEnter={() => setHover(i)} onMouseLeave={() => setHover(null)}>
            <span className="donut-swatch" style={{ background: a.color }} />
            <b>{a.label}</b>
            <span className="donut-pct">{a.pct}%</span>
            <span className="donut-val">{a.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export function HBarChart({ rows, valueKey = "packets", labelKey = "label" }) {
  if (!rows || rows.length === 0) return null;
  const max = Math.max(1, ...rows.map((r) => r[valueKey] || 0));
  return (
    <div className="hbar-list">
      {rows.map((r, i) => (
        <div key={r[labelKey] + i} className="hbar-row">
          <span className="hbar-label mono">{r[labelKey]}</span>
          <div className="hbar-track">
            <div className="hbar-fill" style={{ width: `${((r[valueKey] || 0) / max) * 100}%` }} />
          </div>
          <span className="hbar-val">{r[valueKey]}</span>
        </div>
      ))}
    </div>
  );
}

export function CommunicationMap({ nodes, edges }) {
  const [hoverNode, setHoverNode] = useState(null);
  const [hoverEdge, setHoverEdge] = useState(null);
  if (!nodes || nodes.length === 0) return null;

  const w = 640, h = 300;
  const cx = w / 2, cy = h / 2;
  const radius = Math.min(w, h) / 2 - 74;
  const positions = new Map();
  nodes.forEach((n, i) => {
    const a = (i / nodes.length) * Math.PI * 2 - Math.PI / 2;
    positions.set(n.ip, { x: cx + radius * Math.cos(a), y: cy + radius * Math.sin(a) });
  });
  const maxPackets = Math.max(1, ...edges.map((e) => e.packets || 0));

  const isDimmed = (ip) => hoverNode !== null && hoverNode !== ip
    && !edges.some((e) => (e.from === hoverNode && e.to === ip) || (e.to === hoverNode && e.from === ip));

  const hoveredEdge = hoverEdge !== null ? edges[hoverEdge] : null;
  const hoveredEdgePos = hoveredEdge ? { p1: positions.get(hoveredEdge.from), p2: positions.get(hoveredEdge.to) } : null;

  return (
    <div className="comm-map">
      <svg viewBox={`0 0 ${w} ${h}`} width="100%" style={{ maxHeight: h, display: "block", overflow: "visible" }}>
        {edges.map((e, i) => {
          const p1 = positions.get(e.from);
          const p2 = positions.get(e.to);
          if (!p1 || !p2) return null;
          const strokeW = 1.3 + ((e.packets || 0) / maxPackets) * 4;
          const active = hoverNode === e.from || hoverNode === e.to || hoverEdge === i;
          const dim = hoverNode !== null && !active;
          return (
            <g key={i} onMouseEnter={() => setHoverEdge(i)} onMouseLeave={() => setHoverEdge(null)} style={{ cursor: "pointer" }}>
              <line x1={p1.x} y1={p1.y} x2={p2.x} y2={p2.y}
                stroke="var(--accent)" strokeWidth={hoverEdge === i ? strokeW + 1.4 : strokeW}
                strokeLinecap="round"
                opacity={dim ? 0.1 : hoverEdge === i ? 0.95 : 0.4}
                style={{ transition: "opacity .15s ease, stroke-width .15s ease" }} />
              {/* wider transparent hit-area so short/thin links are still easy to hover */}
              <line x1={p1.x} y1={p1.y} x2={p2.x} y2={p2.y} stroke="transparent" strokeWidth={16} />
            </g>
          );
        })}

        {nodes.map((n) => {
          const p = positions.get(n.ip);
          if (!p) return null;
          const dim = isDimmed(n.ip);
          // Label sits outside the ring — above nodes in the top half,
          // below nodes in the bottom half — so it never crosses the
          // spokes running through the middle or a neighbouring label.
          const labelUp = p.y < cy - 4;
          const labelY = labelUp ? p.y - 20 : p.y + 28;
          return (
            <g key={n.ip} onMouseEnter={() => setHoverNode(n.ip)} onMouseLeave={() => setHoverNode(null)}
               style={{ cursor: "pointer", opacity: dim ? 0.3 : 1, transition: "opacity .15s ease" }}>
              <circle cx={p.x} cy={p.y} r={hoverNode === n.ip ? 9 : 7} fill="var(--surface)" stroke="var(--accent)" strokeWidth="2.2" />
              <circle cx={p.x} cy={p.y} r={2.6} fill="var(--accent)" />
              <rect x={p.x - 52} y={labelY - 12} width="104" height="16" rx="4" fill="var(--surface-2)" opacity={hoverNode === n.ip ? 0.9 : 0} style={{ transition: "opacity .15s ease" }} />
              <text x={p.x} y={labelY} textAnchor="middle" fontSize="10.5" fill="var(--text-strong)" fontFamily="var(--mono)" fontWeight="600">
                {n.ip}
              </text>
            </g>
          );
        })}
      </svg>

      {hoveredEdge && hoveredEdgePos?.p1 && hoveredEdgePos?.p2 && (
        <div
          className="comm-map-tooltip"
          style={{
            left: `${((hoveredEdgePos.p1.x + hoveredEdgePos.p2.x) / 2 / w) * 100}%`,
            top: `${((hoveredEdgePos.p1.y + hoveredEdgePos.p2.y) / 2 / h) * 100}%`,
          }}
        >
          <b>{hoveredEdge.from} → {hoveredEdge.to}</b>
          <span>{hoveredEdge.packets} pkt{hoveredEdge.packets === 1 ? "" : "s"}</span>
        </div>
      )}

      <p className="comm-map-hint">Line thickness reflects packet volume between endpoints — hover a node or connection for exact counts.</p>
    </div>
  );
}
