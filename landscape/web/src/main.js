import { saveAs } from 'file-saver';

import {
  applySearch,
  createGraph,
  createPngBlob,
  filterServices,
  runLayout,
  serializeForDrawio,
} from './graph.js';
import './styles.css';

const iconModules = import.meta.glob('/public/icons/*.svg', {
  eager: true,
  query: '?url',
  import: 'default',
});
const icons = Object.fromEntries(
  Object.entries(iconModules).map(([path, url]) => [
    path.split('/').pop().replace('.svg', ''),
    url,
  ]),
);
const containerIcons = {
  account: icons['container-account'],
  region: icons['container-region'],
  vpc: icons['container-vpc'],
  subnet: icons['container-subnet'],
};

const state = {
  graph: null,
  expandApi: null,
  topology: null,
  enabledServices: new Set(),
};

document.querySelector('#app').innerHTML = `
  <div class="app-shell">
    <header class="topbar">
      <div class="brand">
        <span class="aws-mark"><img class="brand-logo" src="/icons/aws-wordmark.svg" alt="" /></span>
        <div>
          <h1>AWS Architecture</h1>
          <div class="brand-subtitle">AWS Cartography Landscape</div>
        </div>
      </div>
      <div class="connection">
        <span class="status-dot" id="status-dot"></span>
        <div>
          <strong id="status-label">Connecting</strong>
          <small>Local graph · AWS read-only</small>
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
        <section>
          <label class="field-label" for="account">AWS account</label>
          <select id="account" class="select">
            <option value="">All accounts</option>
          </select>
        </section>

        <section>
          <label class="field-label" for="search">Find a resource</label>
          <div class="search-wrap">
            <span aria-hidden="true">⌕</span>
            <input id="search" type="search" placeholder="Name, ID, or service" />
          </div>
          <div class="search-result" id="search-result"></div>
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
          <span>Local only · no AWS writes</span>
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

        <div id="graph" role="application" aria-label="AWS architecture landscape"></div>
        <div class="cloud-key" aria-hidden="true">
          <span class="aws-mark"><img src="/icons/aws-wordmark.svg" alt="" /></span>
          <span>AWS Cloud</span>
        </div>
        <div class="loading" id="loading">
          <div class="spinner"></div>
          <strong>Drawing the AWS architecture</strong>
          <span>Arranging services, components, VPCs, and directional flows…</span>
        </div>
        <div class="legend">
          <span><i class="legend-box component"></i>Component</span>
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
    <div id="toast" class="toast" role="status"></div>
  </div>
`;

const $ = (selector) => document.querySelector(selector);

function showToast(message, variant = 'default') {
  const toast = $('#toast');
  toast.textContent = message;
  toast.className = `toast visible ${variant}`;
  window.setTimeout(() => {
    toast.className = 'toast';
  }, 3200);
}

async function request(path, options) {
  const response = await fetch(path, options);
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload.message || `Request failed (${response.status})`);
  }
  return response;
}

function setHealth(health) {
  $('#status-dot').classList.add('online');
  $('#status-label').textContent = 'Connected';
  $('#status-label').title = `${health.accounts} account(s), ${health.resources} resources`;
}

function enrichIcons(elements) {
  return elements.map((element) => {
    const icon =
      element.data?.kind === 'resource'
        ? `/icons/aws/${encodeURIComponent(
            element.data.icon || 'aws-resource-explorer',
          )}.svg`
        : containerIcons[element.data?.type];
    if (!icon) return element;
    return {
      ...element,
      data: {
        ...element.data,
        image: icon,
      },
    };
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
  $('#loading').classList.remove('hidden');
  if (state.graph) state.graph.destroy();
  const account = $('#account').value;
  const query = new URLSearchParams({ limit: '2500' });
  if (account) query.set('account', account);
  query.set('view', $('#view').value);
  const response = await request(`/api/topology?${query}`);
  state.topology = await response.json();
  const elements = enrichIcons(state.topology.elements);
  const graph = createGraph($('#graph'), elements, renderInspector);
  state.graph = graph.cy;
  state.expandApi = graph.expandApi;
  renderServices(state.topology.stats.services);
  $('#resource-count').textContent =
    state.topology.stats.resources.toLocaleString();
  $('#relationship-count').textContent =
    state.topology.stats.relationships.toLocaleString();
  state.graph.one('layoutstop', () => $('#loading').classList.add('hidden'));
  runLayout(state.graph, $('#layout').value);
  window.setTimeout(() => $('#loading').classList.add('hidden'), 5000);
  if (state.topology.truncated) {
    showToast(`Showing the first ${state.topology.limit} graph nodes`, 'warning');
  }
}

async function init() {
  try {
    const [healthResponse, accountsResponse] = await Promise.all([
      request('/api/health'),
      request('/api/accounts'),
    ]);
    const health = await healthResponse.json();
    const { accounts } = await accountsResponse.json();
    setHealth(health);
    $('#account').insertAdjacentHTML(
      'beforeend',
      accounts
        .map(
          (account) =>
            `<option value="${escapeHtml(account.id)}">${escapeHtml(account.display)}</option>`,
        )
        .join(''),
    );
    await loadTopology();
  } catch (error) {
    $('#loading').innerHTML = `
      <div class="error-symbol">!</div>
      <strong>Landscape could not start</strong>
      <span>${escapeHtml(error.message)}</span>
    `;
    $('#status-label').textContent = 'Disconnected';
    showToast(error.message, 'error');
  }
}

$('#account').addEventListener('change', loadTopology);
$('#view').addEventListener('change', loadTopology);
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
    saveAs(blob, 'cartography-aws-landscape.png');
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
    saveAs(await response.blob(), 'cartography-aws-landscape.drawio');
    showToast('Editable draw.io file exported locally');
  } catch (error) {
    showToast(error.message, 'error');
  }
});

init();
