"""Export the OpenAPI schema to a file.

Usage:
    python -m engine.scripts.export_openapi             # writes to docs/openapi.json
    python -m engine.scripts.export_openapi --yaml       # writes to docs/openapi.yaml
    python -m engine.scripts.export_openapi -o my.json   # custom output path

This allows CI or documentation pipelines to generate the spec without
starting the server.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description="Export ZASEON OpenAPI schema")
    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Output file path (default: docs/openapi.json or docs/openapi.yaml)",
    )
    parser.add_argument(
        "--yaml",
        action="store_true",
        help="Export as YAML instead of JSON",
    )
    args = parser.parse_args()

    # Import the app to get the schema
    from engine.api.main import app

    schema = app.openapi()

    # Determine output path
    ext = "yaml" if args.yaml else "json"
    output_path = Path(args.output) if args.output else Path(f"docs/openapi.{ext}")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if args.yaml:
        try:
            import yaml
        except ImportError:
            print("ERROR: PyYAML is required for YAML export. Install with: pip install pyyaml", file=sys.stderr)
            sys.exit(1)
        content = yaml.dump(schema, default_flow_style=False, sort_keys=False, allow_unicode=True)
    else:
        content = json.dumps(schema, indent=2, ensure_ascii=False)

    output_path.write_text(content, encoding="utf-8")
    print(f"OpenAPI schema exported to {output_path} ({len(content):,} bytes)")


if __name__ == "__main__":
    main()
