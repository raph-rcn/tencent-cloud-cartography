import cytoscape from 'cytoscape';
import { describe, expect, it } from 'vitest';

import { clearRelationshipFocus, focusRelationships } from './graph.js';

function graph() {
  return cytoscape({
    headless: true,
    elements: [
      {
        data: {
          id: 'volume',
          label: 'EBS volume vol-0c892',
          title: 'EBS volume',
        },
        classes: 'resource',
      },
      {
        data: {
          id: 'instance',
          label: 'EC2 instance i-063b05e',
          title: 'EC2 instance',
        },
        classes: 'resource',
      },
      {
        data: {
          id: 'bucket',
          label: 'S3 bucket unrelated',
          title: 'S3 bucket',
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
        resource: 'EBS volume vol-0c892',
        resourceTitle: 'EBS volume',
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
