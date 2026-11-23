// k6 load script (W17 perf). One fixed request: GET /api/v1/accounts/acc-alice-1 with a pre-minted
// DPoP proof + token (verifier JTI_CACHE=off, IAT_WINDOW large, so the same proof is re-verified in full
// - ES256 proof + token signature checks - on every request; only the replay-cache lookup is skipped).
import http from 'k6/http';
import { check } from 'k6';
const MODE = __ENV.MODE;            // "rate" | "max"
const RATE = parseInt(__ENV.RATE || '100');
const DUR = __ENV.DUR || '60s';
export const options = {
  discardResponseBodies: true,
  summaryTrendStats: ['min', 'med', 'avg', 'p(95)', 'p(99)', 'max'],
  scenarios: MODE === 'max'
    ? { max: { executor: 'constant-vus', vus: parseInt(__ENV.VUS || '64'), duration: DUR } }
    : { rate: { executor: 'constant-arrival-rate', rate: RATE, timeUnit: '1s', duration: DUR,
                preAllocatedVUs: Math.max(50, RATE / 2), maxVUs: Math.max(200, RATE * 2) } },
};
const params = { headers: { 'Host': 'api.bench.test', 'Authorization': __ENV.AUTHZ, 'DPoP': __ENV.PROOF,
                            'Accept': 'application/json' } };
export default function () {
  const r = http.get(`http://${__ENV.TARGET}/api/v1/accounts/acc-alice-1`, params);
  check(r, { 'status 200': (x) => x.status === 200 });
}
