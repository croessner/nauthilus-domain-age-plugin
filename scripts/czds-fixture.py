#!/usr/bin/env python3
"""Publish synthetic reserved-domain evidence for isolated compatibility validation."""
import argparse
import io
from pathlib import Path
import tempfile
import time

from czds import Store
from test_czds import zone_file


def main():
    """Exercise the real collector writer without any ICANN credentials or downloads."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='czds-synthetic-') as directory:
        store = Store(Path(directory),reserve_bytes=0)
        store.initialize()
        now = int(time.time())
        store.ingest('com',io.BytesIO(zone_file(['baseline'])),now-86400,minimum=1)
        store.ingest('com',io.BytesIO(zone_file(['baseline','example'])),now-3600,minimum=1)
        store.publish(args.output,now)
        store.close()


if __name__ == '__main__':
    main()
