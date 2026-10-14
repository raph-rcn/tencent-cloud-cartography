const pageSize = 100;
const escape = (value) => String(value ?? '').replace(/[&<>"']/g, (c) => ({'&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;'}[c]));
const accountKey = (r) => r.account && r.account !== 'unknown' ? r.account : `profile:${r.profile || ''}`;

export function filterScopes(rows, filters) {
  const query = (filters.query || '').toLowerCase();
  return rows.filter((r) => (!filters.account || accountKey(r) === filters.account) &&
    (!filters.service || r.service === filters.service) && (!filters.region || r.region === filters.region) &&
    (!filters.state || r.state === filters.state) && (!query || [r.account,r.profile,r.service,r.region,r.reason,...(r.errors || [])].join(' ').toLowerCase().includes(query)));
}

export function outcomeCounts(rows) {
  return Object.fromEntries(['scanned','failed','excluded','unscanned'].map((state) => [state, rows.filter((r) => r.state === state).length]));
}

function table(headers, rows) {
  return `<table><thead><tr>${headers.map((h) => `<th>${escape(h)}</th>`).join('')}</tr></thead><tbody>${rows.length ? rows.join('') : `<tr><td colspan="${headers.length}">No matching records</td></tr>`}</tbody></table>`;
}

const outcome = (r) => `<span class="coverage-state ${escape(r.state)}">${escape(r.state)}${r.partial ? ' · partial' : ''}</span>`;
const row = (cells) => `<tr>${cells.map((c) => `<td>${c}</td>`).join('')}</tr>`;
const options = (values) => [...new Set(values)].sort().map((v) => `<option value="${escape(v)}">${escape(v)}</option>`).join('');

export function showCoverage(container, payload) {
  const data = payload.overview;
  if (!data) throw new Error('Coverage overview unavailable; restart the viewer with the current version.');
  const totals = outcomeCounts(data.scopes);
  container.innerHTML = `<p class="coverage-notice">${data.latest_attempt_failed ? 'Last collection produced no usable inventory. The previous inventory is retained.' : 'Scanned means eligible metadata queries finished; query failures and metadata exclusions remain visible.'} ${data.basis === 'no_collection' ? 'No collection has been attempted yet. Configure a project and sync its inventory to populate these scopes.' : data.basis === 'recorded_operations_only' ? 'This older snapshot has no collection plan: only recorded API scopes are shown; omitted scopes are unknown.' : 'Counts include each planned scope and failed profile attempt, with duplicate-account aliases listed separately.'}</p>
    <p><strong>Inventory:</strong> ${escape(data.inventory_created_at || "Not collected")} <strong>Collection attempt:</strong> ${escape(data.created_at || "Not attempted")} <strong>Region mode:</strong> ${escape(data.region_mode.replaceAll("_", " "))}${data.requested_regions ? ' · restricted to ' + escape(data.requested_regions.join(', ')) : ''}</p>
    <div class="coverage-totals">${Object.entries(totals).map(([state,count]) => `<div><strong>${count}</strong><span>${escape(state)}</span></div>`).join('')}</div>
    <div class="coverage-filters">
      <div><label for="coverage-account">Account / profile</label><select id="coverage-account"><option value="">All accounts / profiles</option>${options(data.scopes.map(accountKey))}</select></div>
      <div><label for="coverage-region">Region</label><select id="coverage-region"><option value="">All regions</option>${options(data.scopes.map((r) => r.region))}</select></div>
      <div><label for="coverage-service">Service</label><select id="coverage-service"><option value="">All services</option>${options(data.scopes.map((r) => r.service))}</select></div>
      <div><label for="coverage-state">Outcome</label><select id="coverage-state"><option value="">All outcomes</option>${options(['scanned','failed','excluded','unscanned'])}</select></div>
      <div class="coverage-search"><label for="coverage-query">Search coverage</label><input id="coverage-query" placeholder="Account, profile, member, service or region" type="search" /></div>
    </div>
    <h3>Account / region / service scopes</h3><div id="coverage-scopes"></div>
    <div class="coverage-pager"><button id="coverage-previous" class="button secondary">Previous scopes</button><span id="coverage-page"></span><button id="coverage-next" class="button secondary">Next scopes</button></div>
    <h3>Profile identity and collection</h3><div id="coverage-profiles"></div>
    <h3>Organization member collection</h3><p>Member discovery does not grant collection access. Members are matched only through the account identity returned for a configured profile.</p><div id="coverage-members"></div>
    <div class="coverage-pager"><button id="members-previous" class="button secondary">Previous members</button><span id="members-page"></span><button id="members-next" class="button secondary">Next members</button></div>
    <h3>Organization enumeration</h3><div id="coverage-organizations"></div>
    <details><summary>API operation evidence</summary><div id="coverage-operations"></div><div class="coverage-pager"><button id="operations-previous" class="button secondary">Previous operations</button><span id="operations-page"></span><button id="operations-next" class="button secondary">Next operations</button></div></details>`;
  const el = (id) => container.querySelector('#' + id);
  let scopesPage = 0, membersPage = 0, operationsPage = 0;
  function slice(values, page, prefix) {
    const pages = Math.max(1, Math.ceil(values.length / pageSize));
    page = Math.min(page, pages - 1);
    el(prefix + '-previous').disabled = page === 0;
    el(prefix + '-next').disabled = page + 1 >= pages;
    el(prefix + '-page').textContent = `${values.length} records · page ${page + 1} of ${pages}`;
    return values.slice(page * pageSize, (page + 1) * pageSize);
  }
  function render() {
    const filters = Object.fromEntries(['account','region','service','state','query'].map((k) => [k, el('coverage-' + k).value]));
    const scoped = filterScopes(data.scopes, filters);
    el('coverage-scopes').innerHTML = table(['Account / profile','Region','Service','Outcome','Queries: successful / failed / excluded','Native resources','Reason'], slice(scoped, scopesPage, 'coverage').map((r) => row([
      escape(r.account || 'Identity unknown') + '<br><small>' + escape(r.profile) + '</small>', escape(r.region),escape(r.service),outcome(r),
      `${r.successful_queries} / ${r.failed_queries} / ${r.excluded_queries}`,escape(r.resource_count ?? 'Unknown'),escape(r.reason) + '<br><small>' + escape((r.errors || []).join(', ')) + '</small>'
    ])));
    const query = filters.query.toLowerCase();
    const profiles = data.profiles.filter((r) => (!filters.account || accountKey(r) === filters.account) && (!query || [r.profile,r.account,r.status,r.error].join(' ').toLowerCase().includes(query)));
    el('coverage-profiles').innerHTML = table(['Profile','Returned account','Outcome','Inventory committed','Reason'], profiles.map((r) => row([escape(r.profile),escape(r.account || 'Identity unknown'),escape(r.status),escape(r.committed),escape(r.error || '') + (r.alias_of ? ' · alias of ' + escape(r.alias_of) : '')])));
    const members = data.organization.filter((r) => (!filters.account || r.member_account === filters.account || r.collector_account === filters.account) && (!filters.state || r.state === filters.state) && (!query || [r.member_account,r.member_name,r.collector_account,...r.matched_profiles,r.reason].join(' ').toLowerCase().includes(query)));
    el('coverage-members').innerHTML = table(['Discovered by account','Member account / name','Matched profiles','Outcome','Reason'], slice(members, membersPage, 'members').map((r) => row([escape(r.collector_account),escape(r.member_account) + '<br>' + escape(r.member_name),escape(r.matched_profiles.join(', ') || 'No verified profile'),outcome(r),escape(r.reason)])));
    el('coverage-organizations').innerHTML = table(['Collector account','Outcome','Enumeration complete','Members observed','Reason'], data.organization_discovery.filter((r) => !filters.account || r.collector_account === filters.account).map((r) => row([escape(r.collector_account),outcome(r),escape(r.enumeration_complete),escape(r.discovered_members),escape(r.reason)])));
    const operations = payload.coverage.map((r) => ({...r, state: ['complete','empty'].includes(r.status) ? 'scanned' : r.status === 'not-queried' || r.error === 'UnsupportedMetadataOnlyProjection' ? 'excluded' : 'failed', reason:r.detail || '', errors:r.error ? [r.error] : []}));
    el('coverage-operations').innerHTML = table(['Account / profile','Region','API','Status','Returned metadata count','Evidence'], slice(filterScopes(operations,filters), operationsPage, 'operations').map((r) => row([escape(r.account) + '<br><small>' + escape(r.profile || '') + '</small>',escape(r.region),escape(r.service + '.' + r.action),escape(r.status),escape(r.count),escape(r.detail || '') + '<br><small>' + escape(r.error || '') + '</small>'])));
  }
  for (const id of ['account','region','service','state','query']) {
    el('coverage-' + id).addEventListener(id === 'query' ? 'input' : 'change', () => {scopesPage = 0; membersPage = 0; operationsPage = 0; render();});
  }
  for (const [id,change] of [['coverage-previous',() => scopesPage--],['coverage-next',() => scopesPage++],['members-previous',() => membersPage--],['members-next',() => membersPage++],['operations-previous',() => operationsPage--],['operations-next',() => operationsPage++]]) {
    el(id).addEventListener('click', () => {change(); render();});
  }
  render();
}
