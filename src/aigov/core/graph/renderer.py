"""Renderers — turn an :class:`AISystemGraph` into HTML or JSON.

The HTML is fully self-contained: dark-themed CSS, the D3 v7 source code, and
the graph payload are all embedded in one document. No CDN is required at
view time — the page works in air-gapped environments where security teams
review findings.
"""
from __future__ import annotations

import json
from importlib.resources import files
from typing import Any, Optional

from aigov.core.graph.schema import AISystemGraph


_D3_VERSION = "7.9.0"
_D3_RESOURCE = "d3.min.js"


def _vendored_d3() -> str:
    """Return the bundled D3 source as a string.

    We prefer ``importlib.resources`` over a hard-coded path so the asset
    works the same in editable installs, wheels, and zipapps. If the asset
    is missing (e.g. an unusual install), we fall back to a sentinel so the
    page still renders something — a missing-D3 banner — rather than a
    silent blank graph.
    """
    try:
        return files("aigov.core.graph._assets").joinpath(_D3_RESOURCE).read_text(
            encoding="utf-8"
        )
    except (FileNotFoundError, ModuleNotFoundError):
        return (
            "console.error('aigov: vendored D3 asset is missing from the install. "
            "Re-install the package or open this HTML alongside an internet "
            "connection.');"
        )


def to_json(graph: AISystemGraph, *, indent: int = 2) -> str:
    return json.dumps(graph.to_dict(), indent=indent, ensure_ascii=False)


def to_html(graph: AISystemGraph, insights: Optional[Any] = None) -> str:
    """Return a self-contained HTML document visualising *graph*.

    The page renders a force-directed D3 graph on the left, with a sticky
    detail panel on the right that fills in when a node is clicked.

    *insights* (optional): a :class:`aigov.core.graph.insights.GraphInsights`
    instance. When provided, the page renders a summary bar at the top, a
    Blast Radius section in the per-node detail panel, and a pulsing glow on
    isolated nodes. When omitted, insights are computed on the fly so any
    caller — direct API user, CLI, test harness — gets a consistent view.
    """
    if insights is None:
        from aigov.core.graph.insights import compute_insights
        insights = compute_insights(graph)
    graph_dict = graph.to_dict()
    graph_dict["insights"] = insights.to_dict()
    payload = json.dumps(graph_dict, ensure_ascii=False)
    metadata = graph.metadata or {}
    timestamp = str(metadata.get("generated_at") or "")
    scan_paths = ", ".join(metadata.get("scan_paths") or [])
    version = str(metadata.get("version") or "")

    # The data payload is JSON, so it's safe inside <script>; the metadata
    # strings are HTML-escaped because they land in element text. The D3
    # source is trusted (we ship it) and is interpolated as a script body —
    # no escaping required for a same-origin literal block.
    html = _HTML_TEMPLATE.format(
        d3_version=_D3_VERSION,
        payload=payload,
        timestamp=_html_escape(timestamp),
        scan_paths=_html_escape(scan_paths),
        version=_html_escape(version),
    )
    # The D3 minified source contains thousands of unescaped ``{`` / ``}``
    # characters, so we splice it in *after* str.format runs rather than as
    # one of the named placeholders — no brace doubling required.
    return html.replace("/*__AIGOV_D3_SOURCE__*/", _vendored_d3())


def _html_escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
    )


# ---------------------------------------------------------------------------
# HTML / CSS / JS template
#
# The double-curly braces ``{{ }}`` inside the script body protect literal
# braces from ``str.format``. Only the named placeholders below are substituted.
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>aigov — AI System Graph</title>
<!-- D3 v{d3_version} vendored inline so this page works offline / air-gapped. -->
<script>
/*__AIGOV_D3_SOURCE__*/
</script>
<style>
  :root {{
    --bg: #0a0e14;
    --bg-elev: #131820;
    --bg-elev-2: #1b212b;
    --border: #2a313d;
    --text: #e6edf3;
    --text-dim: #8b949e;
    --accent: #58a6ff;
    --critical: #ef4444;
    --high: #f97316;
    --medium: #eab308;
    --low: #22c55e;
    --unscored: #6b7280;
  }}
  * {{ box-sizing: border-box; }}
  html, body {{
    margin: 0;
    padding: 0;
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
    font-size: 14px;
    height: 100%;
    overflow: hidden;
  }}
  body {{
    display: flex;
    flex-direction: column;
  }}
  header, #summary-bar {{ flex: 0 0 auto; }}
  header {{
    display: flex;
    align-items: baseline;
    gap: 16px;
    padding: 14px 24px;
    border-bottom: 1px solid var(--border);
    background: var(--bg-elev);
  }}
  header h1 {{
    margin: 0;
    font-size: 16px;
    font-weight: 600;
    letter-spacing: 0.3px;
  }}
  header .meta {{
    color: var(--text-dim);
    font-size: 12px;
  }}
  main {{
    display: grid;
    grid-template-columns: 1fr 360px;
    flex: 1 1 auto;
    min-height: 0;
    position: relative;
  }}
  #graph {{
    width: 100%;
    height: 100%;
    background: var(--bg);
    cursor: grab;
  }}
  #graph:active {{ cursor: grabbing; }}
  #detail-panel {{
    border-left: 1px solid var(--border);
    background: var(--bg-elev);
    overflow-y: auto;
    padding: 18px 20px 60px;
  }}
  #detail-panel h2 {{
    margin: 0 0 4px;
    font-size: 15px;
    font-weight: 600;
  }}
  #detail-panel .placeholder {{
    color: var(--text-dim);
    font-style: italic;
    line-height: 1.5;
  }}
  #detail-panel .field {{
    display: flex;
    gap: 10px;
    padding: 4px 0;
    border-bottom: 1px solid var(--border);
    font-size: 12.5px;
  }}
  #detail-panel .field .k {{
    color: var(--text-dim);
    min-width: 110px;
  }}
  #detail-panel .field .v {{
    color: var(--text);
    word-break: break-all;
  }}
  #detail-panel .section {{
    margin-top: 18px;
  }}
  #detail-panel .section h3 {{
    margin: 0 0 8px;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.6px;
    color: var(--text-dim);
    font-weight: 600;
  }}
  #detail-panel ul {{
    margin: 0;
    padding-left: 18px;
    line-height: 1.5;
  }}
  #detail-panel ul li {{ margin-bottom: 4px; }}
  #detail-panel .edge-row {{
    padding: 10px 12px;
    margin-bottom: 8px;
    background: var(--bg-elev-2);
    border-radius: 4px;
    border-left: 3px solid var(--accent);
    font-size: 12px;
    line-height: 1.5;
  }}
  #detail-panel .edge-header {{
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 4px;
  }}
  #detail-panel .edge-row .rel {{
    color: var(--accent);
    font-weight: 600;
  }}
  #detail-panel .edge-row .conf {{
    color: var(--text-dim);
    background: var(--bg-elev);
    padding: 1px 7px;
    border-radius: 3px;
    font-size: 10.5px;
    font-variant-numeric: tabular-nums;
  }}
  #detail-panel .edge-row .target {{
    color: var(--text);
    margin-bottom: 4px;
  }}
  #detail-panel .edge-row .ev {{
    color: var(--text-dim);
    margin-top: 4px;
    font-style: italic;
    font-size: 11.5px;
  }}
  #detail-panel .edge-row .ev-list {{
    color: var(--text-dim);
    margin: 4px 0 0;
    padding-left: 18px;
    font-style: italic;
    font-size: 11.5px;
    line-height: 1.5;
  }}
  #detail-panel .edge-row .ev-list li {{ margin-bottom: 2px; }}
  #legend {{
    position: absolute;
    bottom: 18px;
    left: 18px;
    background: rgba(19, 24, 32, 0.95);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 12px 14px;
    font-size: 11.5px;
    color: var(--text-dim);
    pointer-events: none;
  }}
  #legend .row {{ display: flex; align-items: center; gap: 8px; margin: 3px 0; }}
  #legend .swatch {{
    width: 12px; height: 12px; border-radius: 50%; display: inline-block;
  }}
  #legend .title {{
    color: var(--text);
    font-weight: 600;
    margin-bottom: 4px;
    text-transform: uppercase;
    font-size: 10.5px;
    letter-spacing: 0.7px;
  }}
  #disclaimer {{
    position: absolute;
    bottom: 18px;
    right: 380px;
    max-width: 360px;
    background: rgba(19, 24, 32, 0.95);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 10px 12px;
    font-size: 11px;
    color: var(--text-dim);
    line-height: 1.5;
    pointer-events: none;
  }}
  /* Graph elements */
  .node circle {{
    stroke: var(--bg);
    stroke-width: 2px;
    cursor: pointer;
    transition: stroke 120ms ease, stroke-width 120ms ease;
  }}
  .node circle:hover {{
    stroke: var(--accent);
    stroke-width: 3px;
  }}
  .node.selected circle {{
    stroke: var(--accent);
    stroke-width: 3px;
  }}
  .node text {{
    fill: var(--text);
    font-size: 11px;
    text-anchor: middle;
    pointer-events: none;
  }}
  .link {{
    stroke: var(--border);
    stroke-opacity: 0.3;
    transition: stroke-opacity 120ms ease;
    cursor: pointer;
  }}
  .link.hover {{
    stroke-opacity: 0.85;
    stroke: var(--accent);
  }}
  /* A wider, fully transparent overlay line catches mouse events so thin
     edges remain hoverable without making them visually heavier. */
  .link-hit {{
    stroke: transparent;
    fill: none;
    cursor: pointer;
  }}
  .link-label {{
    fill: var(--text);
    font-size: 10px;
    text-anchor: middle;
    pointer-events: none;
    paint-order: stroke;
    stroke: var(--bg);
    stroke-width: 3px;
    opacity: 0;
    transition: opacity 120ms ease;
  }}
  .link-label.visible {{
    opacity: 1;
  }}
  /* Tooltip */
  #tooltip {{
    position: absolute;
    pointer-events: none;
    background: var(--bg-elev-2);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 8px 10px;
    font-size: 11.5px;
    line-height: 1.45;
    max-width: 320px;
    opacity: 0;
    transition: opacity 100ms ease;
    z-index: 10;
  }}
  #tooltip .name {{ font-weight: 600; color: var(--text); }}
  #tooltip .row {{ color: var(--text-dim); margin-top: 3px; }}
  /* Filter toolbar — anchored inside main, which is position:relative. */
  #filter-toolbar {{
    position: absolute;
    top: 18px;
    left: 18px;
    display: flex;
    gap: 6px;
    z-index: 5;
  }}
  .filter-btn {{
    background: var(--bg-elev);
    color: var(--text-dim);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 5px 11px;
    font: inherit;
    font-size: 11.5px;
    cursor: pointer;
    transition: background 120ms ease, color 120ms ease, border-color 120ms ease;
  }}
  .filter-btn:hover {{
    background: var(--bg-elev-2);
    color: var(--text);
  }}
  .filter-btn.active {{
    background: var(--accent);
    color: var(--bg);
    border-color: var(--accent);
    font-weight: 600;
  }}
  /* Filter-driven visibility — fade out, animate */
  .node, .link, .link-hit, .link-label {{
    transition: opacity 220ms ease;
  }}
  .node.hidden, .link.hidden, .link-label.hidden {{
    opacity: 0;
    pointer-events: none;
  }}
  .link-hit.hidden {{
    pointer-events: none;
  }}
  /* Summary bar (graph-level insights) */
  #summary-bar {{
    display: flex;
    align-items: center;
    gap: 18px;
    padding: 10px 24px;
    border-bottom: 1px solid var(--border);
    background: var(--bg-elev);
    color: var(--text-dim);
    font-size: 12px;
  }}
  #summary-bar .stat {{
    color: var(--text);
    font-weight: 600;
    font-variant-numeric: tabular-nums;
  }}
  #summary-bar .shadow-warning {{
    margin-left: auto;
    color: var(--medium);
    font-weight: 600;
  }}
  /* Pulsing glow on isolated nodes — they're potential shadow AI and
     should attract a reviewer's eye even at rest. */
  .node.isolated circle {{
    animation: aigov-isolated-pulse 2.4s ease-in-out infinite;
  }}
  @keyframes aigov-isolated-pulse {{
    0%, 100% {{
      stroke: var(--medium);
      stroke-width: 2px;
      stroke-opacity: 0.6;
    }}
    50% {{
      stroke: var(--medium);
      stroke-width: 5px;
      stroke-opacity: 1;
    }}
  }}
  /* Blast radius section in the detail panel */
  #detail-panel .blast-radius {{
    margin-top: 18px;
    padding: 12px 14px;
    border-radius: 5px;
    background: var(--bg-elev-2);
    border-left: 3px solid var(--text-dim);
  }}
  #detail-panel .blast-radius.critical {{ border-left-color: var(--critical); }}
  #detail-panel .blast-radius.high     {{ border-left-color: var(--high); }}
  #detail-panel .blast-radius.medium   {{ border-left-color: var(--medium); }}
  #detail-panel .blast-radius.low      {{ border-left-color: var(--low); }}
  #detail-panel .blast-radius .br-label {{
    text-transform: uppercase;
    font-size: 10.5px;
    letter-spacing: 0.7px;
    color: var(--text-dim);
    font-weight: 600;
    margin-bottom: 6px;
  }}
  #detail-panel .blast-radius .br-level {{
    font-size: 14px;
    font-weight: 700;
    margin-bottom: 8px;
  }}
  #detail-panel .blast-radius.critical .br-level {{ color: var(--critical); }}
  #detail-panel .blast-radius.high     .br-level {{ color: var(--high); }}
  #detail-panel .blast-radius.medium   .br-level {{ color: var(--medium); }}
  #detail-panel .blast-radius.low      .br-level {{ color: var(--low); }}
  #detail-panel .blast-radius .br-row {{
    display: flex;
    justify-content: space-between;
    padding: 3px 0;
    color: var(--text-dim);
    font-size: 12px;
  }}
  #detail-panel .blast-radius .br-row .v {{
    color: var(--text);
    font-variant-numeric: tabular-nums;
  }}
  #detail-panel .blast-radius .br-warning {{
    margin-top: 9px;
    padding: 8px 10px;
    background: rgba(239, 68, 68, 0.08);
    border-radius: 4px;
    color: var(--text);
    font-size: 11.5px;
    line-height: 1.5;
  }}
</style>
</head>
<body>
<header>
  <h1>aigov — AI System Graph</h1>
  <span class="meta">{version}</span>
  <span class="meta">{timestamp}</span>
  <span class="meta">scanned: {scan_paths}</span>
</header>
<div id="summary-bar"></div>
<main>
  <svg id="graph" viewBox="0 0 1200 800" preserveAspectRatio="xMidYMid meet"></svg>
  <div id="filter-toolbar">
    <button id="filter-high-risk" class="filter-btn active" type="button" title="Hide nodes with risk_score &lt; 60">High risk only</button>
    <button id="filter-weak-edges" class="filter-btn" type="button" title="Hide edges with confidence &lt; 0.7">Hide weak edges</button>
    <button id="filter-reset" class="filter-btn" type="button" title="Reset to full graph">Show all</button>
  </div>
  <aside id="detail-panel">
    <p class="placeholder">Click any node to see its details, risk drivers, and the relationships that connect it to other systems. Scroll to zoom · drag empty space to pan.</p>
  </aside>
</main>
<div id="tooltip"></div>
<div id="legend">
  <div class="title">Risk level</div>
  <div class="row"><span class="swatch" style="background:var(--critical)"></span> critical (80–100)</div>
  <div class="row"><span class="swatch" style="background:var(--high)"></span> high (60–79)</div>
  <div class="row"><span class="swatch" style="background:var(--medium)"></span> medium (30–59)</div>
  <div class="row"><span class="swatch" style="background:var(--low)"></span> low (0–29)</div>
  <div class="row"><span class="swatch" style="background:var(--unscored)"></span> unscored</div>
  <div class="title" style="margin-top:8px">Edge style</div>
  <div class="row">━━━ confidence ≥ 0.7</div>
  <div class="row">┄┄┄ confidence &lt; 0.7</div>
  <div class="row" style="margin-top:4px"><span style="opacity:0.6">hover an edge</span> to label it</div>
</div>
<div id="disclaimer">
  Automated signal — not legal advice. Risk scores combine pattern-matched
  classification with deployment context. Consult counsel for compliance decisions.
</div>
<script>
const DATA = {payload};

const COLOR_BY_LEVEL = {{
  critical: getCss('--critical'),
  high:     getCss('--high'),
  medium:   getCss('--medium'),
  low:      getCss('--low'),
}};
const UNSCORED_COLOR = getCss('--unscored');

function getCss(varName) {{
  return getComputedStyle(document.documentElement).getPropertyValue(varName).trim() || '#888';
}}

function nodeRadius(node) {{
  // 20 px floor, 60 px ceiling. Unscored sits at the floor.
  if (node.risk_score == null) return 22;
  const clamped = Math.max(0, Math.min(100, node.risk_score));
  return 20 + (clamped / 100) * 40;
}}

function nodeColor(node) {{
  return COLOR_BY_LEVEL[node.risk_level] || UNSCORED_COLOR;
}}

const svg = d3.select('#graph');
const tooltip = d3.select('#tooltip');
const detail = d3.select('#detail-panel');

// Coordinate system is fixed by the SVG viewBox so layout is predictable
// regardless of how big the browser sized the element.
const SVG_W = 1200;
const SVG_H = 800;
const PADDING = 50;
const CENTER_X = SVG_W / 2;
const CENTER_Y = SVG_H / 2;

// Place every node on a circle around the centre to start. A fresh
// simulation that's never been laid out otherwise spawns nodes at (0,0)
// and only the centring force pulls them in — when the SVG hasn't been
// measured yet that means everything stays in the top-left corner.
DATA.nodes.forEach((n, i) => {{
  const count = Math.max(DATA.nodes.length, 1);
  const angle = (2 * Math.PI * i) / count;
  const r = Math.min(SVG_W, SVG_H) * 0.22;
  n.x = CENTER_X + r * Math.cos(angle);
  n.y = CENTER_Y + r * Math.sin(angle);
}});

// d3.forceLink expects each edge to carry ``source`` and ``target`` fields
// — but our schema uses the more explicit ``source_id`` / ``target_id``
// in the JSON payload. Alias them here so D3 can resolve nodes by id while
// the JSON shape stays self-describing.
const edges = DATA.edges.map(e => ({{
  ...e,
  source: e.source_id,
  target: e.target_id,
}}));

// Derive a file-based display label per node. ``record.name`` (e.g.
// "OpenAI via openai") is repeated across many records — the file name is
// far more useful for visual identification. When two nodes share a base
// filename, prepend parent directories until they're distinguishable; if
// even that doesn't separate them (e.g. multiple MCP servers in the same
// .mcp.json), append the original system name.
const NODE_LABELS = (function buildLabels(nodes) {{
  const stripLine = s => String(s || '').replace(/[:#]L?\\d+$/, '');
  const toPosix = s => stripLine(s).replace(/\\\\/g, '/');
  const parts = new Map();
  nodes.forEach(n => {{
    const path = toPosix(n.source_location);
    const segs = path.split('/').filter(Boolean);
    parts.set(n.id, segs.length ? segs : [n.label]);
  }});

  function tail(node, depth) {{
    const segs = parts.get(node.id);
    const start = Math.max(0, segs.length - depth);
    return segs.slice(start).join('/');
  }}

  // Group nodes by their base filename, then resolve each group.
  const groups = new Map();
  nodes.forEach(n => {{
    const base = tail(n, 1);
    if (!groups.has(base)) groups.set(base, []);
    groups.get(base).push(n);
  }});

  const out = new Map();
  for (const [base, group] of groups) {{
    if (group.length === 1) {{
      out.set(group[0].id, base);
      continue;
    }}
    let resolved = false;
    for (let depth = 2; depth <= 4 && !resolved; depth++) {{
      const candidates = group.map(n => [n.id, tail(n, depth)]);
      const distinct = new Set(candidates.map(([, l]) => l)).size === candidates.length;
      if (distinct) {{
        candidates.forEach(([id, l]) => out.set(id, l));
        resolved = true;
      }}
    }}
    if (!resolved) {{
      // Fall back to "<base> (<system name>)" — happens for MCP servers
      // that share the same .mcp.json file.
      group.forEach(n => out.set(n.id, `${{base}} (${{n.label}})`));
    }}
  }}
  return out;
}})(DATA.nodes);

// ----- Insights — populate the summary bar and prepare per-node lookups -----
const INSIGHTS = DATA.insights || {{ node_insights: {{}}, isolated_nodes: [], risk_clusters: [] }};
const NODE_INSIGHTS = INSIGHTS.node_insights || {{}};
const ISOLATED_IDS = new Set(INSIGHTS.isolated_nodes || []);

(function renderSummaryBar() {{
  const bar = document.getElementById('summary-bar');
  if (!bar) return;
  const n = INSIGHTS.total_nodes || 0;
  const e = INSIGHTS.total_edges || 0;
  const c = (INSIGHTS.risk_clusters || []).length;
  const i = (INSIGHTS.isolated_nodes || []).length;
  const stats = [
    `<span><span class="stat">${{n}}</span> AI system${{n === 1 ? '' : 's'}}</span>`,
    `<span><span class="stat">${{e}}</span> relationship${{e === 1 ? '' : 's'}}</span>`,
    `<span><span class="stat">${{c}}</span> cluster${{c === 1 ? '' : 's'}}</span>`,
    `<span><span class="stat">${{i}}</span> isolated</span>`,
  ];
  let warning = '';
  if (i > 0) {{
    warning = `<span class="shadow-warning">⚠ ${{i}} isolated system${{i === 1 ? '' : 's'}} — potential shadow AI</span>`;
  }}
  bar.innerHTML = stats.join('') + warning;
}})();

// Link distance scales by confidence: a 0.9-confidence edge tightens the
// pair to ~140 px, a 0.5-confidence edge lets them drift to ~200 px.
// Slightly looser than v1 so node circles don't crowd each other.
const linkForce = d3.forceLink(edges)
  .id(d => d.id)
  .distance(d => 260 - 130 * d.confidence)
  .strength(d => 0.3 + d.confidence * 0.4);

const simulation = d3.forceSimulation(DATA.nodes)
  .force('link', linkForce)
  .force('charge', d3.forceManyBody().strength(-900))
  .force('center', d3.forceCenter(CENTER_X, CENTER_Y))
  .force('collide', d3.forceCollide().radius(d => nodeRadius(d) + 28))
  // Soft pull toward the centre on each axis — keeps the layout from
  // drifting against the bounding box clamp below.
  .force('x', d3.forceX(CENTER_X).strength(0.04))
  .force('y', d3.forceY(CENTER_Y).strength(0.04));

// Everything inside ``zoomLayer`` is transformed by the d3.zoom handler
// below — pan and zoom don't move the SVG itself, just this group.
const zoomLayer = svg.append('g').attr('class', 'zoom-layer');

// Render order: visible link first, then a wide invisible "hit" line on
// top so thin edges remain hoverable, then labels (initially hidden).
const linkLayer = zoomLayer.append('g').attr('class', 'links');
const link = linkLayer.selectAll('line.link')
  .data(edges)
  .join('line')
  .attr('class', 'link')
  .attr('stroke-width', d => 0.8 + d.confidence * 1.2)
  .attr('stroke-dasharray', d => d.confidence < 0.7 ? '4 3' : null);

const linkHit = linkLayer.selectAll('line.link-hit')
  .data(edges)
  .join('line')
  .attr('class', 'link-hit')
  .attr('stroke-width', 14);

const linkLabel = zoomLayer.append('g').attr('class', 'link-labels')
  .selectAll('text')
  .data(edges)
  .join('text')
  .attr('class', 'link-label')
  .text(d => d.relationship);

linkHit
  .on('mouseenter', (event, d) => {{
    link.filter(ld => ld === d).classed('hover', true);
    linkLabel.filter(ld => ld === d).classed('visible', true);
    tooltip
      .style('opacity', 1)
      .html(edgeTooltipHtml(d));
    moveTooltip(event);
  }})
  .on('mousemove', moveTooltip)
  .on('mouseleave', (event, d) => {{
    link.filter(ld => ld === d).classed('hover', false);
    linkLabel.filter(ld => ld === d).classed('visible', false);
    tooltip.style('opacity', 0);
  }});

function evidenceList(e) {{
  // ``evidence`` is a list[str] in v0.5.1+. Older snapshots may carry a
  // single string; coerce so the renderer doesn't have to care.
  if (Array.isArray(e.evidence)) return e.evidence.filter(Boolean);
  if (typeof e.evidence === 'string' && e.evidence) return [e.evidence];
  return [];
}}

function edgeTooltipHtml(e) {{
  const sId = (e.source && e.source.id) || e.source_id;
  const tId = (e.target && e.target.id) || e.target_id;
  const a = DATA.nodes.find(n => n.id === sId);
  const b = DATA.nodes.find(n => n.id === tId);
  const aLabel = a ? (NODE_LABELS.get(a.id) || a.label) : sId;
  const bLabel = b ? (NODE_LABELS.get(b.id) || b.label) : tId;
  const conf = Math.round(e.confidence * 100);
  const evidenceRows = evidenceList(e).map(ev =>
    `<div class="row" style="margin-top:4px;color:var(--text);">• ${{escapeHtml(ev)}}</div>`
  ).join('');
  return [
    `<div class="name">${{escapeHtml(e.relationship)}}</div>`,
    `<div class="row">confidence: ${{conf}}%</div>`,
    `<div class="row">${{escapeHtml(aLabel)}} ↔ ${{escapeHtml(bLabel)}}</div>`,
    evidenceRows,
  ].join('');
}}

const node = zoomLayer.append('g').selectAll('g')
  .data(DATA.nodes, d => d.id)
  .join('g')
  .attr('class', d => ISOLATED_IDS.has(d.id) ? 'node isolated' : 'node')
  .call(d3.drag()
    .on('start', (event, d) => {{
      if (!event.active) simulation.alphaTarget(0.3).restart();
      d.fx = d.x; d.fy = d.y;
    }})
    .on('drag', (event, d) => {{
      d.fx = event.x; d.fy = event.y;
    }})
    .on('end', (event, d) => {{
      if (!event.active) simulation.alphaTarget(0);
      d.fx = null; d.fy = null;
    }}));

node.append('circle')
  .attr('r', d => nodeRadius(d))
  .attr('fill', d => nodeColor(d));

node.append('text')
  .attr('dy', d => nodeRadius(d) + 14)
  .text(d => truncate(NODE_LABELS.get(d.id) || d.label, 32));

function truncate(s, n) {{
  if (!s) return '';
  return s.length > n ? s.slice(0, n - 1) + '…' : s;
}}

node
  .on('mouseover', (event, d) => {{
    tooltip
      .style('opacity', 1)
      .html(tooltipHtml(d));
    moveTooltip(event);
  }})
  .on('mousemove', moveTooltip)
  .on('mouseleave', () => tooltip.style('opacity', 0))
  .on('click', (event, d) => {{
    selectNode(d);
    event.stopPropagation();
  }});

svg.on('click', () => {{
  d3.selectAll('.node').classed('selected', false);
  detail.html('<p class="placeholder">Click any node to see its details, risk drivers, and the relationships that connect it to other systems.</p>');
}});

function moveTooltip(event) {{
  const x = event.pageX + 14;
  const y = event.pageY + 14;
  tooltip.style('left', x + 'px').style('top', y + 'px');
}}

function tooltipHtml(d) {{
  const rows = [];
  rows.push(`<div class="name">${{escapeHtml(d.label)}}</div>`);
  rows.push(`<div class="row">${{escapeHtml(d.system_type)}} · ${{escapeHtml(d.provider)}}</div>`);
  if (d.risk_score != null) {{
    rows.push(`<div class="row">risk: ${{d.risk_score}} (${{escapeHtml(d.risk_level || '')}})</div>`);
  }}
  if (d.origin_jurisdiction) {{
    rows.push(`<div class="row">jurisdiction: ${{escapeHtml(d.origin_jurisdiction)}}</div>`);
  }}
  rows.push(`<div class="row">${{escapeHtml(d.source_location)}}</div>`);
  return rows.join('');
}}

function selectNode(d) {{
  d3.selectAll('.node').classed('selected', n => n.id === d.id);
  detail.html(detailHtml(d));
}}

function detailHtml(d) {{
  const tags = d.tags || {{}};
  let drivers = [];
  try {{
    if (tags.risk_drivers) drivers = String(tags.risk_drivers).split(',').filter(Boolean);
  }} catch (e) {{}}
  // Risk drivers are first-class on the JSON record now, not the tags blob.
  // Look in both places to keep older snapshots working.
  if (Array.isArray(d.risk_drivers)) drivers = d.risk_drivers;

  const eu_cat = tags.eu_ai_act_category || '';
  const incomingEdges = DATA.edges.filter(e => {{
    const sId = (e.source && e.source.id) || e.source_id;
    const tId = (e.target && e.target.id) || e.target_id;
    return sId === d.id || tId === d.id;
  }});

  const edgeRows = incomingEdges.map(e => {{
    const sId = (e.source && e.source.id) || e.source_id;
    const tId = (e.target && e.target.id) || e.target_id;
    const otherId = sId === d.id ? tId : sId;
    const other = DATA.nodes.find(n => n.id === otherId);
    const otherLabel = other ? (NODE_LABELS.get(other.id) || other.label) : otherId;
    const conf = Math.round(e.confidence * 100);
    const evList = evidenceList(e);
    const evHtml = evList.length === 0
      ? ''
      : (evList.length === 1
          ? `<div class="ev">${{escapeHtml(evList[0])}}</div>`
          : `<ul class="ev-list">${{evList.map(ev => `<li>${{escapeHtml(ev)}}</li>`).join('')}}</ul>`);
    return `
      <div class="edge-row">
        <div class="edge-header">
          <span class="rel">${{escapeHtml(e.relationship)}}</span>
          <span class="conf">${{conf}}%</span>
        </div>
        <div class="target">→ <strong>${{escapeHtml(otherLabel)}}</strong></div>
        ${{evHtml}}
      </div>`;
  }}).join('');

  return `
    <h2>${{escapeHtml(d.label)}}</h2>
    <div class="field"><span class="k">Provider</span><span class="v">${{escapeHtml(d.provider)}}</span></div>
    <div class="field"><span class="k">System type</span><span class="v">${{escapeHtml(d.system_type)}}</span></div>
    <div class="field"><span class="k">Jurisdiction</span><span class="v">${{escapeHtml(d.origin_jurisdiction || '—')}}</span></div>
    <div class="field"><span class="k">Risk score</span><span class="v">${{d.risk_score == null ? '—' : d.risk_score}} (${{escapeHtml(d.risk_level || 'unscored')}})</span></div>
    <div class="field"><span class="k">Location</span><span class="v">${{escapeHtml(d.source_location)}}</span></div>
    ${{eu_cat ? `<div class="field"><span class="k">EU AI Act</span><span class="v">${{escapeHtml(eu_cat)}}</span></div>` : ''}}
    ${{drivers.length ? `
      <div class="section">
        <h3>Risk drivers</h3>
        <ul>${{drivers.map(x => `<li>${{escapeHtml(x.trim())}}</li>`).join('')}}</ul>
      </div>` : ''}}
    <div class="section">
      <h3>Connections (${{incomingEdges.length}})</h3>
      ${{incomingEdges.length ? edgeRows : '<p class="placeholder">No relationships detected.</p>'}}
    </div>
    ${{blastRadiusHtml(d)}}`;
}}

function blastRadiusHtml(d) {{
  const ins = NODE_INSIGHTS[d.id];
  if (!ins) return '';
  const level = ins.blast_radius || 'low';
  const labels = {{ critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW' }};
  let warning = '';
  if (level === 'critical' || level === 'high') {{
    warning = `<div class="br-warning">⚠ Compromise of this system could impact `
      + `${{ins.degree}} connected system${{ins.degree === 1 ? '' : 's'}}, `
      + `including ${{ins.high_risk_neighbors}} high-risk system${{ins.high_risk_neighbors === 1 ? '' : 's'}}.</div>`;
  }}
  return `
    <div class="blast-radius ${{level}}">
      <div class="br-label">Blast radius</div>
      <div class="br-level">${{labels[level] || level.toUpperCase()}}</div>
      <div class="br-row"><span>Connected systems</span><span class="v">${{ins.degree}}</span></div>
      <div class="br-row"><span>High-risk neighbours</span><span class="v">${{ins.high_risk_neighbors}}</span></div>
      <div class="br-row"><span>Critical neighbours</span><span class="v">${{ins.critical_neighbors}}</span></div>
      ${{warning}}
    </div>`;
}}

function escapeHtml(s) {{
  if (s == null) return '';
  return String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}}

function clamp(value, lo, hi) {{
  return Math.max(lo, Math.min(hi, value));
}}

simulation.on('tick', () => {{
  // Bounding-box constraint — keep every node fully inside the viewBox so
  // they don't drift off-screen when the simulation gets excited.
  DATA.nodes.forEach(d => {{
    const r = nodeRadius(d);
    d.x = clamp(d.x, r + PADDING, SVG_W - r - PADDING);
    d.y = clamp(d.y, r + PADDING, SVG_H - r - PADDING);
  }});
  const setEndpoints = sel => sel
    .attr('x1', d => d.source.x)
    .attr('y1', d => d.source.y)
    .attr('x2', d => d.target.x)
    .attr('y2', d => d.target.y);
  setEndpoints(link);
  setEndpoints(linkHit);
  linkLabel
    .attr('x', d => (d.source.x + d.target.x) / 2)
    .attr('y', d => (d.source.y + d.target.y) / 2);
  node.attr('transform', d => `translate(${{d.x}},${{d.y}})`);
}});

// Zoom + pan: scrolling rescales, click-and-drag on empty space pans.
const zoom = d3.zoom()
  .scaleExtent([0.2, 5])
  .on('zoom', (event) => {{
    zoomLayer.attr('transform', event.transform);
  }});
svg.call(zoom);

// Auto-fit once the simulation cools — picks a transform that puts every
// node comfortably inside the visible area. We only fit on the first
// stabilisation; later drags shouldn't yank the camera around.
let _autoFitDone = false;
simulation.on('end', () => {{
  if (_autoFitDone) return;
  _autoFitDone = true;
  fitToView();
}});

// ----- Filter toolbar -----
// Default to high-risk-only on load. The summary bar still shows the full
// totals so reviewers know there's more to see; the "Show all" button
// reveals every node, "High risk only" re-applies the filter.
const filterState = {{ highRiskOnly: true, hideWeakEdges: false }};

function isNodeHidden(d) {{
  if (!filterState.highRiskOnly) return false;
  return d.risk_score == null || d.risk_score < 60;
}}

function applyFilters() {{
  // Pre-compute the visible-node id set so edges can hide both for confidence
  // *and* because one of their endpoints disappeared.
  const visibleNodeIds = new Set(
    DATA.nodes.filter(d => !isNodeHidden(d)).map(n => n.id)
  );
  function edgeHidden(e) {{
    const sId = (e.source && e.source.id) || e.source_id;
    const tId = (e.target && e.target.id) || e.target_id;
    if (!visibleNodeIds.has(sId) || !visibleNodeIds.has(tId)) return true;
    if (filterState.hideWeakEdges && e.confidence < 0.7) return true;
    return false;
  }}
  node.classed('hidden', isNodeHidden);
  link.classed('hidden', edgeHidden);
  linkHit.classed('hidden', edgeHidden);
  linkLabel.classed('hidden', edgeHidden);
}}

function setBtnState(btnId, active) {{
  const el = document.getElementById(btnId);
  if (el) el.classList.toggle('active', active);
}}

document.getElementById('filter-high-risk').addEventListener('click', () => {{
  filterState.highRiskOnly = !filterState.highRiskOnly;
  setBtnState('filter-high-risk', filterState.highRiskOnly);
  applyFilters();
}});

document.getElementById('filter-weak-edges').addEventListener('click', () => {{
  filterState.hideWeakEdges = !filterState.hideWeakEdges;
  setBtnState('filter-weak-edges', filterState.hideWeakEdges);
  applyFilters();
}});

document.getElementById('filter-reset').addEventListener('click', () => {{
  filterState.highRiskOnly = false;
  filterState.hideWeakEdges = false;
  setBtnState('filter-high-risk', false);
  setBtnState('filter-weak-edges', false);
  applyFilters();
}});

// Apply the default filter immediately so the page loads showing only
// high/critical nodes — the most useful view for a reviewer.
applyFilters();

function fitToView() {{
  if (DATA.nodes.length === 0) return;
  let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
  DATA.nodes.forEach(d => {{
    const r = nodeRadius(d);
    minX = Math.min(minX, d.x - r);
    maxX = Math.max(maxX, d.x + r);
    minY = Math.min(minY, d.y - r);
    maxY = Math.max(maxY, d.y + r);
  }});
  const w = maxX - minX;
  const h = maxY - minY;
  if (w <= 0 || h <= 0) return;
  const margin = 50;
  const scale = Math.min(
    SVG_W / (w + margin * 2),
    SVG_H / (h + margin * 2),
    1.5
  );
  const tx = SVG_W / 2 - scale * (minX + w / 2);
  const ty = SVG_H / 2 - scale * (minY + h / 2);
  svg.transition().duration(500).call(
    zoom.transform,
    d3.zoomIdentity.translate(tx, ty).scale(scale)
  );
}}
</script>
</body>
</html>
"""
