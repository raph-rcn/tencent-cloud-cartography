import { saveAs } from 'file-saver';

import {
  applySearch,
  createGraph,
  createPngBlob,
  filterServices,
  runLayout,
  serializeForDrawio,
} from './graph.js';
import { showCoverage } from './coverage.js';
import './styles.css';

const state = {
  graph: null,
  loadVersion: 0,
  expandApi: null,
  topology: null,
  enabledServices: new Set(),
  setup: false,
  project: new URLSearchParams(window.location.search).get('project') || '',
  projectExplicit: new URLSearchParams(window.location.search).has('project'),
};

document.querySelector('#app').innerHTML = `
  <div class="app-shell">
    <header class="topbar">
      <div class="brand">
        <div>
          <h1><img class="brand-logo" src="/brand/tencent-cloud.svg" alt="Tencent Cloud" /></h1>
          <div class="brand-subtitle">Tencent Cloud Cartography</div>
        </div>
      </div>
      <div class="connection">
        <span class="status-dot" id="status-dot"></span>
        <div>
          <strong id="status-label">Connecting</strong>
          <small id="source-label">Local data · metadata only</small>
        </div>
      </div>
    </header>

    <div class="workspace">
      <aside class="sidebar" id="sidebar">
        <div class="panel-heading">
          <div>
            <strong>Diagram inventory</strong>
            <span>Filter what is shown</span>
          </div>
          <button id="close-sidebar" class="close-button" aria-label="Close inventory">×</button>
        </div>
        <section id="project-field" hidden>
          <label class="field-label" for="project">Project</label>
          <select id="project" class="select"><option value="">Default snapshot</option></select>
        </section>
        <section>
          <label class="field-label" for="account">Tencent Cloud account</label>
          <select id="account" class="select">
            <option value="">All accounts</option>
          </select>
        </section>

        <section>
          <label class="field-label" for="region">Region</label>
          <select id="region" class="select"><option value="">All collected regions</option></select>
        </section>
        <section>
          <a href="/icons.html" target="_blank" rel="noopener">Browse all 896 official product icons ↗</a>
          <button id="coverage-button" class="button secondary">Collection coverage</button>
          <p id="snapshot-status" class="coverage-summary"></p>
        </section>
        <section>
          <label class="field-label" for="search">Find a resource</label>
          <div class="search-wrap">
            <span aria-hidden="true">⌕</span>
            <input id="search" type="search" placeholder="Name, ID, or service" />
          </div>
          <div class="search-result" id="search-result"></div>
        </section>

        <section class="inventory-option">
          <label class="inventory-toggle" for="show-inventory">
            <input id="show-inventory" type="checkbox" />
            <span><strong>Show unresolved inventory</strong><small id="inventory-option-detail">CloudRC-only resources are hidden</small></span>
          </label>
        </section>
        <section class="metrics" aria-label="Landscape summary">
          <div><strong id="resource-count">—</strong><span>Resources</span></div>
          <div><strong id="relationship-count">—</strong><span>Relations</span></div>
          <div><strong id="service-count">—</strong><span>Services</span></div>
        </section>

        <section class="service-section">
          <div class="section-heading">
            <span>Services</span>
            <button class="text-button" id="toggle-services">Clear</button>
          </div>
          <div id="services" class="service-list"></div>
        </section>

        <footer>
          <span class="shield">✓</span>
          <span>Local only · no Tencent Cloud writes</span>
        </footer>
      </aside>
      <div class="panel-scrim" id="panel-scrim"></div>

      <main class="canvas-panel">
        <div class="toolbar">
          <div class="toolbar-group">
            <button id="filters" class="button secondary">Inventory</button>
            <select id="view" class="select compact view-select">
              <option value="architecture">Architecture diagram</option>
              <option value="full">Full relationship graph</option>
            </select>
            <select id="layout" class="select compact">
              <option value="fcose">Auto layout</option>
              <option value="cola">Left-to-right flow</option>
              <option value="grid">Grid</option>
            </select>
            <button id="refresh" class="button ghost">Refresh</button>
            <button id="relayout" class="button ghost">Arrange</button>
            <button id="fit" class="button ghost" title="Fit landscape" aria-label="Fit landscape">Fit</button>
          </div>
          <div class="toolbar-group">
            <button id="collapse" class="button ghost">Collapse</button>
            <button id="expand" class="button ghost">Expand</button>
            <button id="export-png" class="button ghost">PNG</button>
            <button id="export-drawio" class="button primary">Export draw.io</button>
          </div>
        </div>

        <div id="graph" role="application" aria-label="Tencent Cloud architecture landscape"></div>
        <div class="loading" id="loading">
          <div class="spinner"></div>
          <strong>Drawing the Tencent Cloud architecture</strong>
          <span>Arranging services, VPCs, subnets, and relationships…</span>
        </div>
        <div class="legend">
          <span>Collected configuration</span>
          <span><i class="legend-box vpc"></i>VPC</span>
          <span><i class="legend-box subnet"></i>Subnet</span>
          <span><i class="legend-line"></i>Relationship</span>
        </div>
      </main>

      <aside class="inspector" id="inspector" aria-live="polite">
        <button id="close-inspector" class="close-button inspector-close" aria-label="Close details">×</button>
        <div class="inspector-empty">
          <strong>Select a resource</strong>
          <span>Resource details appear here.</span>
        </div>
      </aside>
    </div>
    <dialog id="coverage-dialog"><button id="close-coverage" class="button secondary">Close</button><h2>Collection coverage</h2><p>Review the scopes collected and the reasons for gaps. Profile identity, organization members and API evidence are listed below.</p><div id="coverage-content"></div></dialog>
    <div id="toast" class="toast" role="status"></div>
  </div>
`;

const $ = (selector) => document.querySelector(selector);
const loadingMarkup = $('#loading').innerHTML;
let toastTimer;

function clearToast() {
  window.clearTimeout(toastTimer);
  $('#toast').className = 'toast';
  $('#toast').textContent = '';
}

function showToast(message, variant = 'default') {
  clearToast();
  const toast = $('#toast');
  toast.textContent = message;
  toast.className = `toast visible ${variant}`;
  toastTimer = window.setTimeout(clearToast, 3200);
}

async function request(path, options) {
  if ((state.project || state.projectExplicit) && path.startsWith('/api/') && !path.startsWith('/api/export/') && path !== '/api/projects') {
    const url = new URL(path, window.location.origin);
    url.searchParams.set('project', state.project);
    path = url.pathname + url.search;
  }
  const response = await fetch(path, options);
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload.message || `Request failed (${response.status})`);
  }
  return response;
}

function replaceOptions(select, placeholder, values) {
  const previous = select.value;
  select.replaceChildren(new Option(placeholder, ''), ...values.map(({value,label}) => new Option(label,value)));
  if (values.some(({value}) => value === previous)) select.value = previous;
}

function showFailure(error) {
  state.loadVersion += 1;
  $('#loading').classList.remove('hidden');
  $('#loading').innerHTML = `<div class="error-symbol">!</div><strong>Data unavailable</strong><span>${escapeHtml(error.message)}</span>`;
  $('#status-label').textContent = 'Disconnected';
  $('#status-dot').classList.remove('online');
  showToast(error.message, 'error');
}

function setHealth(health) {
  state.setup = health.mode === 'setup';
  for (const id of ['fit','relayout','layout','collapse','expand','export-png','export-drawio','search','toggle-services']) {
    $(`#${id}`).disabled = state.setup;
  }
  $('#status-dot').classList.add('online');
  $('#status-label').textContent = state.setup ? 'Ready to connect' : health.mode === 'demo' ? 'EXAMPLE DATA' : `Snapshot · ${health.status}`;
  $('#snapshot-status').textContent = `${health.unresolved} unresolved resources · ${new Date(health.created_at).toLocaleString()}`;
  $('#source-label').textContent = health.backend === 'neo4j' ? 'Local graph database · read-only' : 'Local snapshot file · metadata only';
  if (health.latest_attempt_failed) {
    $('#status-label').textContent = health.mode === 'demo' ? 'EXAMPLE DATA · last collection failed' : 'Last collection failed';
    $('#source-label').textContent = `${state.setup ? "No inventory saved" : "Inventory retained"} · attempted ${health.latest_attempt_at}`;
    $('#snapshot-status').textContent = 'Open Collection coverage for failed and unscanned scopes';
  } else if (state.setup) {
    $('#source-label').textContent = health.project ? `Project: ${health.project.id} · no inventory collected` : 'No inventory collected';
    $('#snapshot-status').textContent = 'Choose a project and collect your environment';
  } else if (health.project) {
    $('#source-label').textContent = `Project: ${health.project.id} · metadata only`;
  }
  replaceOptions($('#region'), 'All collected regions', health.regions.map((region) => ({value:region,label:region})));
  $('#status-label').title = `${health.accounts} account(s), ${health.resources} resources`;
}

function enrichIcons(elements) {
  return elements.map((element) => {
    if (!element.data?.icon) return element;
    const name = element.data.icon;
    return { ...element, data: { ...element.data, image: name === 'unmapped.svg' ? '/icons/unmapped.svg' : `/icons/tencent/${encodeURIComponent(name)}` } };
  });
}

function renderServices(services) {
  state.enabledServices = new Set(Object.keys(services));
  $('#service-count').textContent = Object.keys(services).length.toLocaleString();
  $('#services').innerHTML = Object.entries(services)
    .map(
      ([service, count]) => `
        <label class="service-row">
          <input type="checkbox" value="${escapeHtml(service)}" checked />
          <span class="service-check"></span>
          <span class="service-name">${escapeHtml(service)}</span>
          <span class="service-total">${count}</span>
        </label>
      `,
    )
    .join('');
  $('#services').querySelectorAll('input').forEach((input) => {
    input.addEventListener('change', () => {
      if (input.checked) state.enabledServices.add(input.value);
      else state.enabledServices.delete(input.value);
      $('#toggle-services').textContent =
        state.enabledServices.size === 0 ? 'All' : 'Clear';
      filterServices(state.graph, state.enabledServices);
    });
  });
}

function escapeHtml(value) {
  const span = document.createElement('span');
  span.textContent = String(value ?? '');
  return span.innerHTML;
}

function renderInspector(data) {
  if (!data) {
    $('#inspector').classList.remove('open');
    $('#inspector').innerHTML = `
      <button id="close-inspector" class="close-button inspector-close" aria-label="Close details">×</button>
      <div class="inspector-empty">
        <strong>Select a resource</strong>
        <span>Resource details appear here.</span>
      </div>
    `;
    bindInspectorClose();
    return;
  }
  $('#inspector').classList.add('open');
  if (data.relationship) {
    $('#inspector').innerHTML = `
      <button id="close-inspector" class="close-button inspector-close" aria-label="Close details">×</button>
      <div class="inspector-content">
        <div class="inspector-kicker">RELATIONSHIP</div>
        <h2>${escapeHtml(data.label)}</h2>
        <dl>
          <div><dt>Type</dt><dd>${escapeHtml(data.relationship)}</dd></div>
          <div><dt>Source</dt><dd>${escapeHtml(data.source)}</dd></div>
          <div><dt>Target</dt><dd>${escapeHtml(data.target)}</dd></div>
        </dl>
      </div>
    `;
    bindInspectorClose();
    return;
  }
  const properties = Object.entries(data.properties || {})
    .filter(([, value]) => value !== null && value !== '')
    .map(
      ([key, value]) =>
        `<div><dt>${escapeHtml(key.replaceAll('_', ' '))}</dt><dd>${escapeHtml(value)}</dd></div>`,
    )
    .join('');
  const labels = (data.labels || [])
    .map((label) => `<span>${escapeHtml(label)}</span>`)
    .join('');
  const connections = (data.connections || [])
    .map((connection) => {
      const arrow = connection.direction === 'incoming' ? '←' : '→';
      const direction =
        connection.direction === 'incoming' ? 'Incoming' : 'Outgoing';
      return `
        <li>
          <span class="relationship-direction">${arrow} ${escapeHtml(direction)}</span>
          <strong>${escapeHtml(connection.label)}</strong>
          <small>${escapeHtml(connection.resourceTitle || 'Resource')} · ${escapeHtml(connection.resource)}</small>
        </li>
      `;
    })
    .join('');
  $('#inspector').innerHTML = `
    <button id="close-inspector" class="close-button inspector-close" aria-label="Close details">×</button>
    <div class="inspector-content">
      <div class="inspector-kicker">${escapeHtml(data.title || 'RESOURCE')}</div>
      <h2>${escapeHtml(data.label)}</h2>
      <div class="label-chips">${labels}</div>
      ${data.inventoryOnly ? '<p class="inventory-note">Inventory only: discovered by Cloud Resource Center, without native configuration enrichment. Relationships may be incomplete.</p>' : ''}
      ${
        connections
          ? `
            <section class="relationship-summary">
              <h3>Connected resources</h3>
              <ul>${connections}</ul>
            </section>
          `
          : '<p class="no-relationships">No direct relationships are present in this view.</p>'
      }
      <dl>${properties || '<div><dt>Details</dt><dd>No diagram-safe properties</dd></div>'}</dl>
      <p class="inspector-note">Only a small property allowlist is exposed to this UI. Policy documents, credentials, and secret values are never returned.</p>
    </div>
  `;
  bindInspectorClose();
}

function bindInspectorClose() {
  $('#close-inspector')?.addEventListener('click', () => {
    state.graph?.elements().unselect();
    $('#inspector').classList.remove('open');
  });
}

async function loadTopology() {
  if (state.setup) {
    state.graph?.destroy();
    state.graph = null;
    const project = $('#project').value || state.project;
    const setupCommands = project
      ? `tencent-cloud-cartography sync --project ${project}`
      : 'tencent-cloud-cartography projects init my-project --profile default --regions auto\ntencent-cloud-cartography sync --project my-project';
    $('#loading').classList.remove('hidden');
    $('#loading').innerHTML = `<div class="environment-setup"><h2>Connect your Tencent Cloud environment</h2><p>Save a project with your existing TCCLI profiles and regions, then collect its inventory. Each project keeps a separate snapshot.</p><pre>${escapeHtml(setupCommands)}</pre><p>For a source checkout, run these commands through <code>uv run</code> or <code>./landscape/local.sh</code>. Use Refresh after collection. You can also open an existing snapshot with <code>serve --input /path/to/inventory.json</code>, or use a local Neo4j graph.</p><small>No cloud login or API call is needed to open this viewer. Example data is available only through the explicit demo command.</small></div>`;
    $('#resource-count').textContent = '0';
    $('#relationship-count').textContent = '0';
    renderServices({});
    return;
  }
  $('#loading').innerHTML = loadingMarkup;
  $('#loading').classList.remove('hidden');
  const loadVersion = ++state.loadVersion;
  const account = $('#account').value;
  const query = new URLSearchParams({ limit: '2500' });
  if (account) query.set('account', account);
  if ($('#region').value) query.set('region', $('#region').value);
  query.set('view', $('#view').value);
  query.set('include_inventory', $('#show-inventory').checked ? '1' : '0');
  const response = await request(`/api/topology?${query}`);
  const topology = await response.json();
  if (loadVersion !== state.loadVersion) return;
  if (state.graph) state.graph.destroy();
  state.topology = topology;
  const elements = enrichIcons(state.topology.elements);
  const graph = createGraph($('#graph'), elements, renderInspector);
  state.graph = graph.cy;
  state.expandApi = graph.expandApi;
  renderServices(state.topology.stats.services);
  $('#inventory-option-detail').textContent = `${state.topology.stats.unresolvedAvailable} inventory-only resources available · ${$('#show-inventory').checked ? 'shown' : 'hidden'}`;
  $('#resource-count').textContent =
    state.topology.stats.resources.toLocaleString();
  $('#relationship-count').textContent =
    state.topology.stats.relationships.toLocaleString();
  state.graph.one('layoutstop', () => { if (loadVersion === state.loadVersion) $('#loading').classList.add('hidden'); });
  runLayout(state.graph, $('#layout').value);
  window.setTimeout(() => { if (loadVersion === state.loadVersion) $('#loading').classList.add('hidden'); }, 5000);
  if (state.topology.truncated) {
    showToast(`Showing the first ${state.topology.limit} graph nodes`, 'warning');
  }
}

async function init() {
  try {
    const [healthResponse, accountsResponse, projectsResponse] = await Promise.all([
      request('/api/health'),
      request('/api/accounts'),
      request('/api/projects'),
    ]);
    const health = await healthResponse.json();
    const { accounts } = await accountsResponse.json();
    const { projects } = await projectsResponse.json();
    $('#project-field').hidden = !projects.length;
    replaceOptions($('#project'), 'Default snapshot', projects.map((project) => ({value:project.id,label:project.id})));
    $('#project').value = state.project || health.project?.id || '';
    clearToast();
    setHealth(health);
    replaceOptions($('#account'), 'All accounts', accounts.map((account) => ({value:account.id,label:account.display})));
    await loadTopology();
  } catch (error) {
    showFailure(error);
  } finally {
    $('#refresh').disabled = false;
  }
}

$('#project').addEventListener('change', () => {
  const value = $('#project').value;
  const url = new URL(window.location.href);
  if (value) url.searchParams.set('project', value);
  else url.searchParams.set('project', '');
  window.location.href = url.href;
});

$('#refresh').addEventListener('click', () => {
  $('#refresh').disabled = true;
  init();
});
const reloadTopology = () => loadTopology().catch(showFailure);
$('#account').addEventListener('change', reloadTopology);
$('#region').addEventListener('change', reloadTopology);
$('#view').addEventListener('change', reloadTopology);
$('#show-inventory').addEventListener('change', reloadTopology);
$('#relayout').addEventListener('click', () =>
  runLayout(state.graph, $('#layout').value),
);
$('#layout').addEventListener('change', () =>
  runLayout(state.graph, $('#layout').value),
);
$('#fit').addEventListener('click', () => state.graph.fit(undefined, 56));
$('#collapse').addEventListener('click', () => {
  state.expandApi.collapseAll();
  state.graph.fit(undefined, 80);
});
$('#expand').addEventListener('click', () => {
  state.expandApi.expandAll();
  runLayout(state.graph, $('#layout').value);
});
$('#search').addEventListener('input', (event) => {
  const count = applySearch(state.graph, event.target.value);
  $('#search-result').textContent = event.target.value
    ? `${count} match${count === 1 ? '' : 'es'}`
    : '';
});
$('#toggle-services').addEventListener('click', () => {
  const inputs = [...$('#services').querySelectorAll('input')];
  const shouldEnable = state.enabledServices.size === 0;
  state.enabledServices = new Set(
    shouldEnable ? inputs.map((input) => input.value) : [],
  );
  inputs.forEach((input) => {
    input.checked = shouldEnable;
  });
  $('#toggle-services').textContent = shouldEnable ? 'Clear' : 'All';
  filterServices(state.graph, state.enabledServices);
});
const setInventoryOpen = (open) => {
  $('#sidebar').classList.toggle('open', open);
  $('#panel-scrim').classList.toggle('open', open);
};
$('#filters').addEventListener('click', () => setInventoryOpen(true));
$('#close-sidebar').addEventListener('click', () => setInventoryOpen(false));
$('#panel-scrim').addEventListener('click', () => setInventoryOpen(false));
bindInspectorClose();
$('#export-png').addEventListener('click', async () => {
  const button = $('#export-png');
  button.disabled = true;
  try {
    const { blob, width, height } = await createPngBlob(state.graph);
    saveAs(blob, 'tencent-cloud-cartography.png');
    showToast(
      `PNG exported locally · ${width.toLocaleString()} × ${height.toLocaleString()}`,
    );
  } catch (error) {
    showToast(error.message, 'error');
  } finally {
    button.disabled = false;
  }
});
$('#export-drawio').addEventListener('click', async () => {
  try {
    const payload = serializeForDrawio(state.graph);
    const response = await request('/api/export/drawio', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    saveAs(await response.blob(), 'tencent-cloud-cartography.drawio');
    showToast('Editable draw.io file exported locally');
  } catch (error) {
    showToast(error.message, 'error');
  }
});

$('#coverage-button').addEventListener('click', async () => {
  try {
    showCoverage($('#coverage-content'), await (await request('/api/coverage')).json());
    $('#coverage-dialog').showModal();
  } catch (error) { showToast(error.message, 'error'); }
});
$('#close-coverage').addEventListener('click', () => $('#coverage-dialog').close());
init();
