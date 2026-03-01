# ZASEON Load Testing

Load tests for the ZASEON API using [k6](https://k6.io/).

## Prerequisites

```bash
brew install k6          # macOS
# or: https://k6.io/docs/get-started/installation/
```

## Quick start

```bash
# Smoke test against local dev
k6 run infra/load-testing/k6-config.js

# Against staging with auth
k6 run --env BASE_URL=https://staging.zaseon.io \
       --env ZASEON_API_KEY=your-key \
       infra/load-testing/k6-config.js
```

## Scenarios

| Scenario   | VUs | Duration | Purpose                                 |
| ---------- | --- | -------- | --------------------------------------- |
| **smoke**  | 5   | 1 min    | Sanity — all endpoints respond          |
| **load**   | 50  | 5 min    | Normal traffic baseline                 |
| **stress** | 200 | 3 min    | Peak capacity limit                     |
| **spike**  | 300 | 1 min    | Sudden burst resilience                 |
| **soak**   | 30  | 30 min   | Memory leak / connection pool detection |

## Run a single scenario

```bash
k6 run --env BASE_URL=http://localhost:8000 \
       -e K6_SCENARIO=smoke \
       infra/load-testing/k6-config.js
```

## Thresholds

- **p95 latency** < 500 ms (all endpoints)
- **p99 latency** < 2 s
- **Quick-scan p95** < 10 s
- **Health p99** < 100 ms
- **Error rate** < 5%
- **Scan duration p95** < 30 s

## Output to Grafana / InfluxDB

```bash
k6 run --out influxdb=http://localhost:8086/k6 \
       infra/load-testing/k6-config.js
```
