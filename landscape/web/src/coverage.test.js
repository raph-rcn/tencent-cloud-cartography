import { describe, expect, it } from 'vitest';
import { authenticationSummary, filterScopes, outcomeCounts } from './coverage.js';

const rows = [
  {account:'100',profile:'prod',region:'eu-frankfurt',service:'cvm',state:'scanned',reason:'metadata_queries_finished'},
  {account:'200',profile:'dev',region:'ap-singapore',service:'vpc',state:'failed',reason:'query_failure',errors:['UnauthorizedOperation']},
  {account:null,profile:'expired',region:'unknown',service:'cvm',state:'unscanned',reason:'profile_identity_unavailable'},
  {account:'100',profile:'prod',region:'ap-singapore',service:'cvm',state:'excluded',reason:'region_restriction'},
];
describe('coverage overview', () => {
  it('accounts for all four outcomes without calling excluded scopes scanned', () => {
    expect(outcomeCounts(rows)).toEqual({scanned:1,failed:1,excluded:1,unscanned:1});
  });
  it('filters account, region, service and outcome together', () => {
    expect(filterScopes(rows,{account:'100',region:'ap-singapore',service:'cvm',state:'excluded'})).toEqual([rows[3]]);
    expect(filterScopes(rows,{account:'100',state:'failed'})).toEqual([]);
  });
  it('keeps unknown-account profile attempts selectable and searches failure reasons', () => {
    expect(filterScopes(rows,{account:'profile:expired'})).toEqual([rows[2]]);
    expect(filterScopes(rows,{query:'UNAUTHORIZED'})).toEqual([rows[1]]);
    expect(filterScopes(rows,{query:'prod'})).toHaveLength(2);
  });
  it('does not truncate the counts to the visible page', () => {
    expect(outcomeCounts(Array(251).fill(rows[0])).scanned).toBe(251);
    expect(filterScopes(Array(251).fill(rows[0]),{})).toHaveLength(251);
  });
});


describe('profile authentication status', () => {
  it('shows provider, expired session and the exact local login command', () => {
    expect(authenticationSummary({authentication:{provider:'sso',status:'login-required',refreshes:2,code:'SsoSessionExpired',remediation:'tccli sso login --profile client-a'}})).toBe('sso · login-required · 2 refreshes · SsoSessionExpired · tccli sso login --profile client-a');
  });
  it('does not imply that legacy snapshots verified credential refresh', () => {
    expect(authenticationSummary({})).toBe('Not recorded in this snapshot');
    expect(authenticationSummary({authentication:{provider:'oauth',status:'ready',refreshes:1,code:'',remediation:''}})).toBe('oauth · ready · 1 refreshes');
  });
});
