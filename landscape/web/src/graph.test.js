import cytoscape from 'cytoscape';
import { describe, expect, it } from 'vitest';

import { clearRelationshipFocus, focusRelationships, filterServices, serializeForDrawio } from './graph.js';

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
