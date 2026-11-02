"""Exercise acquisition semantics without contacting ICANN."""
import gzip
import io
import os
from pathlib import Path
import struct
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock

import czds


def zone_file(names):
    """Encode a small realistic zone with apex SOA and duplicate delegations."""
    records = ['com. 86400 IN SOA ns.com. hostmaster.com. ( 1 2 3 4 5 )', 'com. IN NS ns.com.']
    for name in names:
        records.extend([f'{name}.com. IN NS ns.example.', '\tIN NS ns2.example.', f'ns.{name}.com. IN A 192.0.2.1'])
    return gzip.compress(('\n'.join(records)+'\n').encode())


class CollectorContract(unittest.TestCase):
    """Keep baselines, historic observations and publications independent."""

    def test_each_eligible_download_has_fresh_authentication(self):
        """Long zone processing cannot leave the next download with an expired token."""
        class ExpiringClient:
            """Model a token that expires during processing of each completed zone."""

            def __init__(self):
                """Keep authentication state independent of test account files."""
                self.fresh=False
                self.logins=0

            def authenticate(self):
                """Issue one fresh token without exposing a credential value."""
                self.fresh=True
                self.logins+=1

            def links(self):
                """Return two approved zones so a long first import affects the second."""
                return {zone:czds.API+'/czds/downloads/'+zone+'.zone' for zone in ['com','org']}

            def get(self,url):
                """Require a fresh token before a new data transfer starts."""
                if not self.fresh:
                    raise ValueError('expired test token')
                self.fresh=False
                return io.BytesIO(b'unused synthetic body')

        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            original=czds.Store
            store=original(root,reserve_bytes=0)
            store.initialize()
            store.close()
            minimum=root/'counts.json'
            minimum.write_text(czds.json.dumps({zone:1000 for zone in czds.ZONES}))
            client=ExpiringClient()
            arguments=['czds','--state',str(root),'--output',str(root/'pub'),'--credentials','unused','--minimum-counts',str(minimum)]
            with mock.patch.object(sys,'argv',arguments),mock.patch.object(czds,'Client',return_value=client),mock.patch.object(czds,'Store',side_effect=lambda path,reporter=None:original(path,reserve_bytes=0,reporter=reporter)),mock.patch.object(original,'ingest'),mock.patch.object(czds.signal,'signal'),mock.patch.object(czds.signal,'alarm'),mock.patch.object(czds,'RUN_DEADLINE',None),mock.patch.object(czds,'DEADLINE_EXPIRED',False):
                czds.main()
            self.assertLessEqual(client.logins,1+len(czds.ZONES))

    def test_baseline_addition_reappearance(self):
        """Initial domains stay unknown; additions survive disappearance."""
        with tempfile.TemporaryDirectory() as directory:
            store = czds.Store(Path(directory), reserve_bytes=0)
            store.initialize()
            baseline = ['old'+str(i) for i in range(20)]
            for stamp, names in [(1000000,baseline), (1100000,baseline+['new']), (1200000,baseline), (1300000,baseline+['new'])]:
                store.ingest('com', io.BytesIO(zone_file(names)), stamp, minimum=1)
            output = Path(directory)/'pub'
            store.publish(output, now=1300000)
            data = (output/'com.idx').read_bytes()
            header = struct.unpack('>8sQQQ16s32s48s',data[:128])
            self.assertEqual((header[1],header[2],header[3]),(1300000,1000000,1))
            self.assertEqual(struct.unpack('>Q',data[-8:])[0],1100000)
            store.close()

    def test_failed_import_preserves_generation(self):
        """Incomplete gzip and suspicious counts cannot update history."""
        with tempfile.TemporaryDirectory() as directory:
            store = czds.Store(Path(directory), reserve_bytes=0)
            store.initialize()
            store.ingest('com',io.BytesIO(zone_file(['old','other'])),1000000,minimum=1)
            for data in [zone_file(['new'])[:-5], zone_file([]), gzip.compress(b'new.com. IN NS ns.example.\n')]:
                with self.assertRaises((ValueError,EOFError,OSError)):
                    store.ingest('com',io.BytesIO(data),1100000,minimum=1)
                self.assertEqual(store.db.execute('SELECT checked FROM zones WHERE zone="com"').fetchone()[0],1000000)
                self.assertFalse((Path(directory)/'stage.sqlite').exists())
            store.close()

    def test_missing_history_requires_initialization(self):
        """Loss of local state never silently resets observation history."""
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                czds.Store(Path(directory),reserve_bytes=0).require_initialized()

    def test_origin_and_url_boundaries(self):
        """Reject path tricks and unsupported remote destinations."""
        for url in ['http://czds-api.icann.org/czds/downloads/com.zone','https://evil.example/com.zone','https://czds-api.icann.org.evil.example/com.zone','https://czds-api.icann.org/czds/downloads/com.zone?token=x']:
            with self.assertRaises(ValueError):
                czds.download_zone(url)
        self.assertEqual(czds.download_zone('https://czds-api.icann.org/czds/downloads/com.zone'),'com')

    def test_attempt_ledger_survives_restart(self):
        """Failed and interrupted attempts still consume their 24-hour slot."""
        with tempfile.TemporaryDirectory() as directory:
            store = czds.Store(Path(directory),reserve_bytes=0)
            store.initialize()
            self.assertTrue(store.begin_attempt('com',1000000))
            store.close()
            store.require_initialized()
            self.assertFalse(store.begin_attempt('com',1086399))
            self.assertTrue(store.begin_attempt('com',1086400))
            store.close()

    def test_publication_failure_recovers_committed_dates(self):
        """A crash between commit and rename never resets observation time."""
        with tempfile.TemporaryDirectory() as directory:
            store = czds.Store(Path(directory),reserve_bytes=0)
            store.initialize()
            store.ingest('com',io.BytesIO(zone_file(['old'])),1000000,minimum=1)
            output = Path(directory)/'pub'
            store.publish(output,1000000)
            previous = (output/'com.idx').read_bytes()
            store.ingest('com',io.BytesIO(zone_file(['old','new'])),1100000,minimum=1)
            with mock.patch.object(czds.os,'replace',side_effect=OSError('simulated failed rename')):
                with self.assertRaises(OSError):
                    store.publish(output,1200000)
            self.assertEqual((output/'com.idx').read_bytes(),previous)
            store.publish(output,1200000)
            data = (output/'com.idx').read_bytes()
            self.assertEqual(czds.HEADER.unpack(data[:128])[1],1100000)
            self.assertEqual(struct.unpack('>Q',data[-8:])[0],1100000)
            store.close()

    def test_budget_and_directives_fail_closed(self):
        """Storage pressure and external zone includes cannot advance history."""
        with tempfile.TemporaryDirectory() as directory:
            store = czds.Store(Path(directory),reserve_bytes=0)
            store.initialize()
            with mock.patch.object(czds.shutil,'disk_usage',return_value=mock.Mock(free=-1)):
                with self.assertRaises(ValueError):
                    store.ingest('com',io.BytesIO(zone_file(['old'])),1000000,minimum=1)
            for content in [b'$INCLUDE /etc/passwd\n',b'$ORIGIN evil.org.\n',b'com. IN SOA ns. host. ( 1 2 3\n']:
                with self.assertRaises(ValueError):
                    list(czds.records(io.BytesIO(gzip.compress(content)),'com',lambda:None))
            store.close()

    def test_malformed_evidence_records(self):
        """Reject invalid delegation targets and SOA names before accepting evidence."""
        valid = gzip.decompress(zone_file(['new']))
        for content in [valid.replace(b'ns.example.',b'@@@'),valid.replace(b'ns.com. hostmaster.com.',b'@@@ !!!'),valid.replace(b'ns.example.',b'ns.example..')]:
            with self.assertRaises(ValueError):
                list(czds.records(io.BytesIO(gzip.compress(content)),'com',lambda:None))

    def test_acquisition_notices_remain_private(self):
        """Commit notices and provenance with history, never into the public index."""
        with tempfile.TemporaryDirectory() as directory:
            store = czds.Store(Path(directory),reserve_bytes=0)
            store.initialize()
            content = b'; Registry copyright notice\n'+gzip.decompress(zone_file(['old']))
            store.ingest('com',io.BytesIO(gzip.compress(content)),1000000,minimum=1)
            metadata = store.db.execute('SELECT metadata FROM acquisitions').fetchone()[0]
            self.assertIn('Registry copyright notice',metadata)
            output = Path(directory)/'pub'
            store.publish(output,1000000)
            self.assertNotIn(b'Registry copyright notice',(output/'com.idx').read_bytes())
            store.close()

    def test_empty_comments_are_bounded(self):
        """Empty comments consume metadata budget instead of growing an unbounded list."""
        content = b';\n'*65537+gzip.decompress(zone_file(['old']))
        with self.assertRaises(ValueError):
            list(czds.records(io.BytesIO(gzip.compress(content)),'com',lambda:None))

    def test_sqlite_deadline_translation_remains_fatal(self):
        """SQLite callback translation cannot consume the complete-run deadline."""
        with tempfile.TemporaryDirectory() as directory:
            store = czds.Store(Path(directory),reserve_bytes=0)
            store.initialize()
            with mock.patch.object(czds,'RUN_DEADLINE',0),mock.patch.object(czds,'DEADLINE_EXPIRED',False):
                store.db.set_progress_handler(store.progress,1)
                with self.assertRaises(sqlite3.OperationalError):
                    store.db.execute('SELECT 1').fetchall()
                with self.assertRaises(czds.CollectorDeadline):
                    czds.ensure_deadline()
            store.db.set_progress_handler(None,0)
            store.close()

    @unittest.skipUnless(Path('/proc/self/fd').is_dir(),'Linux collector temporary-file accounting')
    def test_unlinked_sort_runs_count_once(self):
        """Unlinked sorter files consume the budget, including duplicate descriptors."""
        with tempfile.TemporaryDirectory() as directory:
            store=czds.Store(Path(directory),reserve_bytes=0)
            store.initialize()
            linked=sum(path.stat().st_size for path in Path(directory).iterdir() if path.is_file())
            with tempfile.TemporaryFile(dir=directory) as scratch:
                scratch.truncate(4<<20)
                duplicate=os.dup(scratch.fileno())
                try:
                    with mock.patch.object(czds,'STATE_LIMIT',linked+(6<<20)):
                        store.check_budget()
                    with mock.patch.object(czds,'STATE_LIMIT',linked+(2<<20)):
                        with self.assertRaises(ValueError):
                            store.check_budget()
                finally:
                    os.close(duplicate)
            store.close()

    def test_adjacent_suppression_and_non_adjacent_deduplication(self):
        """Bound repeated grouped delegations while keeping final SQL deduplication."""
        data=zone_file(['old','other','old'])
        hashes=list(czds.records(io.BytesIO(data),'com',lambda:None))
        self.assertEqual(len(hashes),3)
        self.assertEqual(hashes[0],hashes[2])
        with tempfile.TemporaryDirectory() as directory:
            store=czds.Store(Path(directory),reserve_bytes=0)
            store.initialize()
            store.ingest('com',io.BytesIO(data),1000000,minimum=1)
            self.assertEqual(store.db.execute('SELECT count FROM zones').fetchone()[0],2)
            store.close()


if __name__ == '__main__':
    unittest.main()
