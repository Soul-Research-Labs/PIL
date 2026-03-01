# ZASEON Python SDK

Python client library for the [ZASEON](https://github.com/OWNER/zaseon) smart contract security platform.

## Installation

```bash
pip install zaseon-sdk
```

## Quick Start

```python
import asyncio
from zaseon_sdk import ZaseonClient

async def main():
    async with ZaseonClient(api_key="zsk_your_key_here") as client:
        # Quick scan source code (60s)
        result = await client.quick_scan(
            source_code='pragma solidity ^0.8.0; contract Vault { ... }',
            contract_name="Vault",
        )
        print(f"Score: {result.security_score}")
        for finding in result.findings:
            print(f"  [{finding.severity.value}] {finding.title}")

        # Full async campaign
        scan_id = await client.start_scan(ScanConfig(
            source_code="...",
            mode="deep",
            enable_symbolic=True,
        ))
        result = await client.wait_for_scan(scan_id)

asyncio.run(main())
```

## Sync Usage

```python
from zaseon_sdk import ZaseonClient

client = ZaseonClient(api_key="zsk_your_key_here")
result = client.quick_scan_sync(source_code="pragma solidity ^0.8.0; ...")
print(result.findings)
client.close_sync()
```

## API Reference

### `ZaseonClient`

| Method                                           | Description                           |
| ------------------------------------------------ | ------------------------------------- |
| `quick_scan(source_code, contract_name)`         | 60-second quick fuzz                  |
| `quick_scan_address(address, chain)`             | Quick-scan deployed contract          |
| `start_scan(config)`                             | Start full 18-phase campaign          |
| `get_scan(scan_id)`                              | Get scan status/results               |
| `wait_for_scan(scan_id, poll_interval, timeout)` | Poll until complete                   |
| `symbolic_analysis(source_code)`                 | Symbolic execution                    |
| `differential_test(source_v1, source_v2)`        | Cross-version diff                    |
| `list_findings(scan_id, severity, cursor)`       | Paginated findings                    |
| `get_report(scan_id, format)`                    | Download report (json/sarif/html/pdf) |
| `get_analytics(days, granularity)`               | Analytics summary                     |
| `login(email, password)`                         | Login and set token                   |

## License

MIT
