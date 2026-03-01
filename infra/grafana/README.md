# ZASEON Grafana Dashboards

Pre-built dashboards for monitoring the ZASEON platform.

## Dashboards

| Dashboard           | UID               | Description                                                                            |
| ------------------- | ----------------- | -------------------------------------------------------------------------------------- |
| **Scan Operations** | `zaseon-scan-ops` | Scan throughput, duration, queue depth, findings by severity/category, coverage trends |
| **API Performance** | `zaseon-api-perf` | Request rate, latency percentiles, HTTP status codes, error rates, rate limiting       |
| **Infrastructure**  | `zaseon-infra`    | CPU/memory/disk, PostgreSQL connections, Redis hit rate, Celery worker utilization     |

## Import

1. Open Grafana → **Dashboards** → **Import**
2. Upload the JSON file or paste its contents
3. Select your Prometheus data source when prompted

## Required Prometheus targets

| Exporter                                                                       | Job name        | Purpose                                          |
| ------------------------------------------------------------------------------ | --------------- | ------------------------------------------------ |
| ZASEON engine metrics                                                          | `zaseon-engine` | App-level scan/finding counters, HTTP histograms |
| ZASEON worker metrics                                                          | `zaseon-worker` | Celery task metrics                              |
| [postgres_exporter](https://github.com/prometheus-community/postgres_exporter) | `postgres`      | DB connection & query stats                      |
| [redis_exporter](https://github.com/oliver006/redis_exporter)                  | `redis`         | Memory, hit rate, connected clients              |
| [node_exporter](https://github.com/prometheus/node_exporter)                   | `node`          | CPU, memory, disk, network                       |

## Prometheus scrape config (example)

```yaml
scrape_configs:
  - job_name: zaseon-engine
    static_configs:
      - targets: ["engine:8000"]
    metrics_path: /internal/metrics

  - job_name: zaseon-worker
    static_configs:
      - targets: ["worker:9100"]

  - job_name: postgres
    static_configs:
      - targets: ["postgres-exporter:9187"]

  - job_name: redis
    static_configs:
      - targets: ["redis-exporter:9121"]
```
