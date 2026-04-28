"""Renderers — turn an :class:`AISystemGraph` into HTML or JSON.

The HTML is fully self-contained: dark-themed CSS, the D3 v7 source code, and
the graph payload are all embedded in one document. No CDN is required at
view time — the page works in air-gapped environments where security teams
review findings.
"""
from __future__ import annotations

import json
from importlib.resources import files
from typing import Any

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


def to_html(graph: AISystemGraph) -> str:
    """Return a self-contained HTML document visualising *graph*.

    The page renders a force-directed D3 graph on the left, with a sticky
    detail panel on the right that fills in when a node is clicked.
    """
    payload = json.dumps(graph.to_dict(), ensure_ascii=False)
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
    height: calc(100% - 51px);
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
    padding: 8px 10px;
    margin-bottom: 6px;
    background: var(--bg-elev-2);
    border-radius: 4px;
    border-left: 3px solid var(--accent);
    font-size: 12px;
    line-height: 1.45;
  }}
  #detail-panel .edge-row .rel {{
    color: var(--accent);
    font-weight: 600;
  }}
  #detail-panel .edge-row .conf {{
    color: var(--text-dim);
    margin-left: 6px;
  }}
  #detail-panel .edge-row .ev {{
    color: var(--text-dim);
    margin-top: 4px;
    font-style: italic;
  }}
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
    stroke-opacity: 0.85;
  }}
  .link-label {{
    fill: var(--text-dim);
    font-size: 9.5px;
    text-anchor: middle;
    pointer-events: none;
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
</style>
</head>
<body>
<header>
  <h1>aigov — AI System Graph</h1>
  <span class="meta">{version}</span>
  <span class="meta">{timestamp}</span>
  <span class="meta">scanned: {scan_paths}</span>
</header>
<main>
  <svg id="graph"></svg>
  <aside id="detail-panel">
    <p class="placeholder">Click any node to see its details, risk drivers, and the relationships that connect it to other systems.</p>
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

const width  = () => svg.node().clientWidth;
const height = () => svg.node().clientHeight;

// Use D3's id accessor against node.id strings rather than indices.
const linkForce = d3.forceLink(DATA.edges)
  .id(d => d.id)
  .distance(140)
  .strength(d => 0.2 + d.confidence * 0.6);

const simulation = d3.forceSimulation(DATA.nodes)
  .force('link', linkForce)
  .force('charge', d3.forceManyBody().strength(-280))
  .force('center', d3.forceCenter(width() / 2, height() / 2))
  .force('collide', d3.forceCollide().radius(d => nodeRadius(d) + 12));

// d3.forceLink rewrote each edge so source / target are the actual node objects.
// Use the link data as our edge data going forward.
const edges = DATA.edges;

const link = svg.append('g').selectAll('line')
  .data(edges)
  .join('line')
  .attr('class', 'link')
  .attr('stroke-width', d => 1 + d.confidence * 2)
  .attr('stroke-dasharray', d => d.confidence < 0.7 ? '4 3' : null);

const linkLabel = svg.append('g').selectAll('text')
  .data(edges)
  .join('text')
  .attr('class', 'link-label')
  .text(d => d.relationship);

const node = svg.append('g').selectAll('g')
  .data(DATA.nodes, d => d.id)
  .join('g')
  .attr('class', 'node')
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
  .text(d => truncate(d.label, 28));

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
    const otherLabel = other ? other.label : otherId;
    return `
      <div class="edge-row">
        <span class="rel">${{escapeHtml(e.relationship)}}</span>
        <span class="conf">conf ${{e.confidence.toFixed(2)}}</span>
        — connects to <strong>${{escapeHtml(otherLabel)}}</strong>
        <div class="ev">${{escapeHtml(e.evidence)}}</div>
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
    </div>`;
}}

function escapeHtml(s) {{
  if (s == null) return '';
  return String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}}

simulation.on('tick', () => {{
  link
    .attr('x1', d => d.source.x)
    .attr('y1', d => d.source.y)
    .attr('x2', d => d.target.x)
    .attr('y2', d => d.target.y);
  linkLabel
    .attr('x', d => (d.source.x + d.target.x) / 2)
    .attr('y', d => (d.source.y + d.target.y) / 2);
  node.attr('transform', d => `translate(${{d.x}},${{d.y}})`);
}});

window.addEventListener('resize', () => {{
  simulation.force('center', d3.forceCenter(width() / 2, height() / 2));
  simulation.alpha(0.3).restart();
}});
</script>
</body>
</html>
"""
