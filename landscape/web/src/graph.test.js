import cytoscape from 'cytoscape';
import { describe, expect, it, vi } from 'vitest';

import { layoutOptions, runLayout, arrangeCompoundGrid, clearRelationshipFocus, focusRelationships, filterServices, serializeForDrawio } from './graph.js';

function graph() {
  return cytoscape({
    headless: true,
    elements: [
      {
        data: {
          id: 'volume',
          label: 'CBS disk disk-demo',
          title: 'CBS disk',
        },
        classes: 'resource',
      },
      {
        data: {
          id: 'instance',
          label: 'CVM instance ins-demo',
          title: 'CVM instance',
        },
        classes: 'resource',
      },
      {
        data: {
          id: 'bucket',
          label: 'COS bucket unrelated',
          title: 'COS bucket',
        },
        classes: 'resource',
      },
      {
        data: {
          id: 'attached',
          source: 'volume',
          target: 'instance',
          label: 'Attached To',
          relationship: 'ATTACHED_TO',
        },
      },
    ],
  });
}

describe('relationship focus', () => {
  it('highlights incident arrows and directly connected resources', () => {
    const cy = graph();
    const result = focusRelationships(cy, cy.$id('instance'));

    expect(cy.$id('attached').hasClass('relationship-path')).toBe(true);
    expect(cy.$id('volume').hasClass('connected-resource')).toBe(true);
    expect(cy.$id('bucket').hasClass('relationship-muted')).toBe(true);
    expect(result.connections).toEqual([
      {
        direction: 'incoming',
        label: 'Attached To',
        relationship: 'ATTACHED_TO',
        resource: 'CBS disk disk-demo',
        resourceTitle: 'CBS disk',
      },
    ]);
  });

  it('clears every relationship focus class', () => {
    const cy = graph();
    focusRelationships(cy, cy.$id('instance'));
    clearRelationshipFocus(cy);

    expect(cy.$('.relationship-path')).toHaveLength(0);
    expect(cy.$('.connected-resource')).toHaveLength(0);
    expect(cy.$('.relationship-muted')).toHaveLength(0);
  });
});


describe('filters and exports', () => {
  it('hides edges when either endpoint is filtered', () => {
    const cy = graph();
    filterServices(cy, new Set(['CVM instance']));
    expect(cy.$id('instance').hasClass('filtered')).toBe(false);
    expect(cy.$id('volume').hasClass('filtered')).toBe(true);
    expect(cy.$id('attached').hasClass('filtered')).toBe(true);
    cy.destroy();
  });
  it('retains hierarchy and icon identifiers in editable exports', () => {
    const cy = cytoscape({ headless: true, elements: [
      {data: {id:'vpc',type:'vpc',label:'VPC'}},
      {data: {id:'vm',parent:'vpc',type:'resource',icon:'en-cloud-virtual-machine.svg',label:'CVM'}}
    ]});
    const payload = serializeForDrawio(cy);
    const vm = payload.nodes.find(n => n.id === 'vm');
    expect(vm.parent).toBe('vpc');
    expect(vm.icon).toBe('en-cloud-virtual-machine.svg');
    cy.destroy();
  });
  it('keeps a boundary with visible children but hides an excluded empty boundary', () => {
    const cy = cytoscape({headless:true,elements:[
      {data:{id:'vpc',title:'VPC'},classes:'vpc inventory-node'},
      {data:{id:'vm',parent:'vpc',title:'CVM'},classes:'resource inventory-node'},
      {data:{id:'empty',title:'VPC'},classes:'vpc inventory-node'}
    ]});
    filterServices(cy,new Set(['CVM']));
    expect(cy.$id('vpc').hasClass('filtered')).toBe(false);
    expect(cy.$id('empty').hasClass('filtered')).toBe(true);
    cy.destroy();
  });
});


describe('compound grid', () => {
  it('keeps nested region and service siblings separate while retaining edges', () => {
    const cy = cytoscape({ headless: true, styleEnabled: true,
      style: [{ selector: 'node', style: { width: 78, height: 78, padding: 38 } }],
      elements: [
        {data:{id:'account'}},
        {data:{id:'frankfurt',parent:'account'}},
        {data:{id:'global',parent:'account'}},
        {data:{id:'compute',parent:'frankfurt'}},
        {data:{id:'storage',parent:'frankfurt'}},
        {data:{id:'vm',parent:'compute'}},
        {data:{id:'vm2',parent:'compute'}},
        {data:{id:'disk',parent:'storage'}},
        {data:{id:'dns',parent:'global'}},
        {data:{id:'attachment',source:'disk',target:'vm'}},
      ]});
    arrangeCompoundGrid(cy);
    const disjoint = (a, b) => a.x2 < b.x1 || b.x2 < a.x1 || a.y2 < b.y1 || b.y2 < a.y1;
    for (const [a, b] of [['frankfurt','global'], ['compute','storage'], ['vm','vm2']]) {
      expect(disjoint(cy.$id(a).boundingBox(), cy.$id(b).boundingBox())).toBe(true);
    }
    cy.nodes(':parent').forEach(parent => {
      const p = parent.boundingBox();
      parent.children().forEach(child => {
        const c = child.boundingBox();
        expect(c.x1).toBeGreaterThan(p.x1);
        expect(c.x2).toBeLessThan(p.x2);
        expect(c.y1).toBeGreaterThan(p.y1);
        expect(c.y2).toBeLessThan(p.y2);
      });
    });
    expect(serializeForDrawio(cy).edges).toHaveLength(1);
    const positions = cy.nodes().map(n => ({...n.position()}));
    arrangeCompoundGrid(cy);
    expect(cy.nodes().map(n => n.position())).toEqual(positions);
    cy.destroy();
  });
});


it('stops an unfinished layout before its delayed update can overwrite Grid', () => {
  vi.useFakeTimers();
  function DelayedLayout(options) { this.cy = options.cy; }
  DelayedLayout.prototype.run = function () {
    this.timer = setTimeout(() => this.cy.nodes().positions({x: 9999, y: 9999}), 100);
  };
  DelayedLayout.prototype.stop = function () { clearTimeout(this.timer); };
  cytoscape('layout', 'delayed-regression', DelayedLayout);
  layoutOptions.delayed = {name: 'delayed-regression'};
  const cy = graph();
  try {
    runLayout(cy, 'delayed');
    runLayout(cy, 'grid');
    const positions = cy.nodes().map(n => ({...n.position()}));
    vi.advanceTimersByTime(150);
    expect(cy.nodes().map(n => n.position())).toEqual(positions);
    expect(cy.$id('volume').position()).not.toEqual(cy.$id('instance').position());
  } finally {
    cy.destroy();
    delete layoutOptions.delayed;
    vi.useRealTimers();
  }
});
