import cytoscape from 'cytoscape';
import cola from 'cytoscape-cola';
import expandCollapse from 'cytoscape-expand-collapse';
import fcose from 'cytoscape-fcose';

cytoscape.use(fcose);
cytoscape.use(cola);
expandCollapse(cytoscape);

export const layoutOptions = {
  fcose: {
    name: 'fcose',
    quality: 'proof',
    randomize: true,
    animate: true,
    animationDuration: 650,
    fit: true,
    padding: 72,
    nodeDimensionsIncludeLabels: true,
    uniformNodeDimensions: false,
    packComponents: true,
    samplingType: true,
    sampleSize: 25,
    nodeSeparation: 260,
    piTol: 0.0000001,
    nodeRepulsion: () => 14000,
    idealEdgeLength: () => 190,
    edgeElasticity: () => 0.32,
    nestingFactor: 0.35,
    numIter: 3500,
    tile: true,
    tilingPaddingVertical: 64,
    tilingPaddingHorizontal: 64,
    gravity: 0.18,
    gravityRangeCompound: 1.2,
    gravityCompound: 0.8,
    gravityRange: 3.8,
    initialEnergyOnIncremental: 0.3,
  },
  cola: {
    name: 'cola',
    animate: true,
    maxSimulationTime: 2400,
    fit: true,
    padding: 72,
    nodeDimensionsIncludeLabels: true,
    randomize: true,
    avoidOverlap: true,
    handleDisconnected: true,
    convergenceThreshold: 0.01,
    nodeSpacing: () => 48,
    flow: { axis: 'x', minSeparation: 180 },
  },
  grid: {
    name: 'grid',
    animate: true,
    fit: true,
    padding: 72,
    avoidOverlap: true,
    avoidOverlapPadding: 56,
    condense: false,
  },
};

const graphStyle = [
  {
    selector: 'node',
    style: {
      'font-family': '"Amazon Ember", Arial, Helvetica, sans-serif',
      color: '#16191f',
      label: 'data(label)',
      'text-wrap': 'wrap',
      'text-max-width': 190,
      'overlay-opacity': 0,
    },
  },
  {
    selector: '.resource',
    style: {
      width: 78,
      height: 78,
      shape: 'rectangle',
      'background-color': '#ffffff',
      'background-opacity': 0,
      'background-image': 'data(image)',
      'background-fit': 'contain',
      'background-width': '74px',
      'background-height': '74px',
      'border-opacity': 0,
      'text-valign': 'bottom',
      'text-halign': 'center',
      'text-margin-y': 20,
      'font-size': 14,
      'font-weight': 500,
      color: '#16191f',
      padding: 8,
    },
  },
  {
    selector: '.resource:selected',
    style: {
      'border-color': '#ec7211',
      'border-width': 3,
      'border-opacity': 1,
      'background-color': '#fffaf0',
      'background-opacity': 0.5,
    },
  },
  {
    selector: '.resource.search-match',
    style: {
      'border-color': '#007eb9',
      'border-width': 4,
      'border-opacity': 1,
      'background-color': '#e9f6fb',
      'background-opacity': 0.7,
    },
  },
  {
    selector: '.resource.connected-resource',
    style: {
      'border-color': '#007eb9',
      'border-width': 4,
      'border-opacity': 1,
      'background-color': '#e9f6fb',
      'background-opacity': 0.72,
    },
  },
  {
    selector: 'node:parent[image]',
    style: {
      'background-image': 'data(image)',
      'background-image-opacity': 1,
      'background-image-containment': 'over',
      'background-fit': 'none',
      'background-repeat': 'no-repeat',
      'background-width': '34px',
      'background-height': '34px',
      'background-position-x': '0%',
      'background-position-y': '0%',
      'background-offset-x': 0,
      'background-offset-y': 0,
    },
  },
  {
    selector: '.account',
    style: {
      shape: 'rectangle',
      padding: 74,
      'background-color': '#ffffff',
      'background-opacity': 0,
      'border-color': '#16191f',
      'border-width': 2,
      'text-valign': 'top',
      'text-halign': 'left',
      'text-justification': 'left',
      'text-margin-x': 120,
      'text-margin-y': 18,
      'text-max-width': '160px',
      'font-size': 24,
      'font-weight': 500,
      color: '#16191f',
    },
  },
  {
    selector: '.region',
    style: {
      shape: 'rectangle',
      padding: 58,
      'background-color': '#ffffff',
      'background-opacity': 0,
      'border-color': '#5a6c86',
      'border-width': 2,
      'border-style': 'dashed',
      'text-valign': 'top',
      'text-halign': 'left',
      'text-justification': 'left',
      'text-margin-x': 145,
      'text-margin-y': 18,
      'text-max-width': '300px',
      'font-size': 17,
      'font-weight': 500,
      color: '#5a6c86',
    },
  },
  {
    selector: '.vpc',
    style: {
      shape: 'rectangle',
      padding: 50,
      'background-color': '#ffffff',
      'background-opacity': 0,
      'border-color': '#8c4fff',
      'border-width': 2,
      'text-valign': 'top',
      'text-halign': 'left',
      'text-justification': 'left',
      'text-margin-x': 170,
      'text-margin-y': 18,
      'text-max-width': '420px',
      'font-size': 17,
      'font-weight': 600,
      color: '#8c4fff',
    },
  },
  {
    selector: '.availabilityZone',
    style: {
      shape: 'rectangle',
      padding: 24,
      'background-color': '#ffffff',
      'background-opacity': 0,
      'border-color': '#ec7211',
      'border-width': 2,
      'border-style': 'dashed',
      'text-valign': 'top',
      'text-halign': 'center',
      'text-margin-y': 8,
      'font-size': 16,
      'font-weight': 500,
      color: '#b45309',
    },
  },
  {
    selector: '.subnet',
    style: {
      shape: 'rectangle',
      padding: 42,
      'background-color': '#e9f3e6',
      'background-opacity': 0.86,
      'border-color': '#1d8102',
      'border-width': 2,
      'text-valign': 'top',
      'text-halign': 'left',
      'text-justification': 'left',
      'text-margin-x': 165,
      'text-margin-y': 18,
      'text-max-width': '360px',
      'font-size': 16,
      'font-weight': 600,
      color: '#1d8102',
    },
  },
  {
    selector: '.component',
    style: {
      shape: 'rectangle',
      padding: 38,
      'background-color': '#ffffff',
      'background-opacity': 0.05,
      'border-color': '#5a6c86',
      'border-width': 2,
      'border-style': 'dashed',
      'text-valign': 'top',
      'text-halign': 'left',
      'text-margin-x': 12,
      'text-margin-y': 12,
      'font-size': 16,
      'font-weight': 500,
      color: '#5a6c86',
    },
  },
  {
    selector: 'edge',
    style: {
      width: 2,
      'curve-style': 'taxi',
      'taxi-direction': 'rightward',
      'taxi-turn': 34,
      'taxi-turn-min-distance': 20,
      'line-color': '#545b64',
      'target-arrow-color': '#545b64',
      'target-arrow-shape': 'triangle',
      'arrow-scale': 1.15,
      opacity: 0.92,
      label: '',
    },
  },
  {
    selector: 'edge.membership',
    style: {
      width: 1.5,
      'line-style': 'dashed',
      'line-color': '#64748b',
      'target-arrow-color': '#64748b',
      'target-arrow-shape': 'vee',
      opacity: 0.75,
    },
  },
  {
    selector: 'edge:selected',
    style: {
      width: 3,
      'line-color': '#ec7211',
      'target-arrow-color': '#ec7211',
      opacity: 1,
      label: 'data(label)',
      'font-size': 11,
      color: '#545b64',
      'text-background-color': '#ffffff',
      'text-background-opacity': 1,
      'text-background-padding': 3,
    },
  },
  {
    selector: 'edge.relationship-path',
    style: {
      width: 4,
      'line-color': '#ec7211',
      'target-arrow-color': '#ec7211',
      'target-arrow-shape': 'triangle',
      'arrow-scale': 1.35,
      opacity: 1,
      label: 'data(label)',
      'font-size': 12,
      'font-weight': 600,
      color: '#232f3e',
      'text-background-color': '#ffffff',
      'text-background-opacity': 1,
      'text-background-padding': 4,
      'text-border-color': '#ec7211',
      'text-border-width': 1,
      'text-border-opacity': 1,
    },
  },
  {
    selector: '.resource.relationship-muted, edge.relationship-muted',
    style: {
      opacity: 0.18,
    },
  },
  {
    selector: 'edge.cy-expand-collapse-meta-edge',
    style: {
      width: 3,
      'line-color': '#ec7211',
      'target-arrow-color': '#ec7211',
      'target-arrow-shape': 'triangle',
    },
  },
  {
    selector: '.filtered',
    style: {
      display: 'none',
    },
  },
];

export function clearRelationshipFocus(cy) {
  cy.elements().removeClass(
    'connected-resource relationship-path relationship-muted',
  );
}

export function focusRelationships(cy, node) {
  clearRelationshipFocus(cy);
  const edges = node.connectedEdges().not('.filtered');
  const connectedNodes = edges
    .connectedNodes('.resource')
    .not(node)
    .not('.filtered');
  const unrelatedNodes = cy
    .nodes('.resource')
    .not(node)
    .not(connectedNodes)
    .not('.filtered');
  const unrelatedEdges = cy.edges().not(edges).not('.filtered');

  cy.batch(() => {
    connectedNodes.addClass('connected-resource');
    edges.addClass('relationship-path');
    unrelatedNodes.addClass('relationship-muted');
    unrelatedEdges.addClass('relationship-muted');
  });

  const connections = edges.map((edge) => {
    const outgoing = edge.source().id() === node.id();
    const connectedNode = outgoing ? edge.target() : edge.source();
    return {
      direction: outgoing ? 'outgoing' : 'incoming',
      label: edge.data('label'),
      relationship: edge.data('relationship'),
      resource: connectedNode.data('label'),
      resourceTitle: connectedNode.data('title'),
    };
  });
  return { edges, connectedNodes, connections };
}

export function createGraph(container, elements, onSelect) {
  const cy = cytoscape({
    container,
    elements,
    style: graphStyle,
    minZoom: 0.06,
    maxZoom: 3,
    boxSelectionEnabled: true,
    selectionType: 'single',
  });

  const expandApi = cy.expandCollapse({
    layoutBy: null,
    fisheye: false,
    animate: true,
    undoable: false,
    cueEnabled: true,
    expandCollapseCuePosition: 'top-left',
    expandCollapseCueSize: 16,
    expandCollapseCueLineSize: 9,
  });

  cy.on('select', 'node.resource', (event) => {
    const node = event.target;
    const { connections } = focusRelationships(cy, node);
    onSelect({ ...node.data(), connections });
  });
  cy.on('unselect', 'node.resource', () => {
    if (!cy.$('node.resource:selected').length) {
      clearRelationshipFocus(cy);
      if (!cy.$('edge:selected').length) onSelect(null);
    }
  });
  cy.on('select', 'edge', (event) => {
    clearRelationshipFocus(cy);
    onSelect(event.target.data());
  });
  cy.on('unselect', 'edge', () => {
    if (!cy.$(':selected').length) onSelect(null);
  });
  cy.on('tap', (event) => {
    if (event.target !== cy) return;
    cy.elements().unselect();
    clearRelationshipFocus(cy);
    onSelect(null);
  });

  return { cy, expandApi };
}

export function runLayout(cy, name) {
  cy.layout(layoutOptions[name] || layoutOptions.fcose).run();
}

export function applySearch(cy, query) {
  cy.nodes().removeClass('search-match');
  if (!query.trim()) return 0;
  const normalized = query.trim().toLowerCase();
  const matches = cy
    .nodes('.resource')
    .filter((node) =>
      [node.data('label'), node.data('title'), node.data('primaryLabel')]
        .filter(Boolean)
        .some((value) => String(value).toLowerCase().includes(normalized)),
    );
  matches.addClass('search-match');
  if (matches.length) {
    cy.animate({ fit: { eles: matches, padding: 150 }, duration: 350 });
  }
  return matches.length;
}

export function filterServices(cy, enabledServices) {
  cy.batch(() => {
    cy.nodes('.resource').forEach((node) => {
      node.toggleClass('filtered', !enabledServices.has(node.data('title')));
    });
    cy.edges().forEach((edge) => {
      edge.toggleClass(
        'filtered',
        edge.source().hasClass('filtered') || edge.target().hasClass('filtered'),
      );
    });
    cy.nodes(':parent')
      .sort((a, b) => b.ancestors().length - a.ancestors().length)
      .forEach((node) => {
        const visibleChildren = node
          .children()
          .some((child) => !child.hasClass('filtered'));
        node.toggleClass('filtered', !visibleChildren);
      });
  });
}

export async function createPngBlob(cy) {
  const bounds = cy
    .elements(':visible')
    .boundingBox({ includeLabels: true, includeOverlays: false });
  const width = Math.max(1, bounds.w);
  const height = Math.max(1, bounds.h);
  const maxDimension = 4096;
  const maxArea = 12_000_000;
  const scale = Math.max(
    0.05,
    Math.min(
      2,
      maxDimension / width,
      maxDimension / height,
      Math.sqrt(maxArea / (width * height)),
    ),
  );
  const blob = await cy.png({
    output: 'blob-promise',
    full: true,
    scale,
    maxWidth: maxDimension,
    maxHeight: maxDimension,
    bg: '#ffffff',
  });
  if (!(blob instanceof Blob) || blob.size < 1024) {
    throw new Error('PNG renderer returned an empty image');
  }
  return {
    blob,
    width: Math.round(width * scale),
    height: Math.round(height * scale),
  };
}

export function serializeForDrawio(cy) {
  const nodes = cy
    .nodes(':visible')
    .map((node) => {
      const box = node.boundingBox({ includeLabels: true, includeOverlays: false });
      return {
        id: node.id(),
        label: node.data('label'),
        type: node.data('type'),
        icon: node.data('icon'),
        depth: node.ancestors().length,
        x: box.x1,
        y: box.y1,
        width: box.w,
        height: box.h,
      };
    });
  const visibleIds = new Set(nodes.map((node) => node.id));
  const edges = cy
    .edges(':visible')
    .filter(
      (edge) => visibleIds.has(edge.source().id()) && visibleIds.has(edge.target().id()),
    )
    .map((edge) => ({
      id: edge.id(),
      source: edge.source().id(),
      target: edge.target().id(),
      label: edge.data('label'),
    }));
  return { nodes, edges };
}
