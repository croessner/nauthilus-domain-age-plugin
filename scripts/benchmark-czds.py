#!/usr/bin/env python3
"""Measure synthetic baseline/update work beyond the SQLite cache without network access."""
import argparse
import gzip
import json
from pathlib import Path
import resource
import sys
import tempfile
import time

from czds import Store,emit_event


def write_zone(path, count):
    """Stream realistic duplicate delegations and glue without keeping names in memory."""
    with gzip.open(path,'wb',compresslevel=1) as output:
        output.write(b'com. 86400 IN SOA ns.example. hostmaster.example. ( 1 2 3 4 5 )\n')
        for index in range(count):
            domain = 'n'+str(index)+'.com.'
            output.write((domain+' 86400 IN NS ns.example.\n\tIN NS ns2.example.\nns.'+domain+' IN A 192.0.2.1\n').encode())


def main():
    """Report elapsed time, peak disk and RSS for baseline plus existing-history update."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--count',type=int,default=1000000)
    parser.add_argument('--directory',type=Path,default=Path('/tmp'))
    options = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='czds-benchmark-',dir=options.directory) as name:
        root = Path(name)
        state, publication = root/'state',root/'publication'
        store = Store(state,reserve_bytes=0,reporter=emit_event)
        store.initialize()
        peak = [0]
        original = store.check_budget

        def measured_budget():
            """Include transient stage and rollback journal files in the peak."""
            original()
            peak[0] = max(peak[0],store.state_bytes())

        store.check_budget = measured_budget
        measurements = []
        for label,count,stamp in [('baseline',options.count,1000000),('update',options.count+options.count//100,1100000)]:
            path = root/'zone.gz'
            write_zone(path,count)
            emit_event('benchmark_zone_generated',domains=count)
            started = time.monotonic()
            with path.open('rb') as source:
                store.ingest('com',source,stamp,minimum=1)
            store.publish(publication,stamp)
            measurements.append({'case':label,'domains':count,'seconds':round(time.monotonic()-started,3),'history_bytes':(state/'history.sqlite').stat().st_size})
            print(json.dumps({'progress':measurements[-1]}),flush=True)
        store.close()
        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        print(json.dumps({'measurements':measurements,'peak_state_bytes':peak[0],'peak_rss_bytes':rss if sys.platform=='darwin' else rss*1024}),flush=True)


if __name__ == '__main__':
    main()
