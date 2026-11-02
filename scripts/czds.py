#!/usr/bin/env python3
"""Collect authorized CZDS zones into bounded durable observation history."""
import argparse
from contextlib import contextmanager
import fcntl
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import signal
import sqlite3
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ZONES = ('biz', 'com', 'info', 'net', 'online', 'org', 'shop', 'site', 'top', 'xyz')
AUTH = 'https://account-api.icann.org/api/authenticate'
API = 'https://czds-api.icann.org'
GIB = 1 << 30
HISTORY_LIMIT = 12 * GIB
STATE_LIMIT = 40 * GIB
MAX_RECORDS = 10_000_000
WINDOW = 90 * 86400
HEADER = struct.Struct('>8sQQQ16s32s48s')
LABEL = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z', re.ASCII)
RUN_DEADLINE = None
DEADLINE_EXPIRED = False


class CollectorDeadline(BaseException):
    """Escape per-zone recovery when the complete run deadline expires."""


def ensure_deadline():
    """Preserve deadline expiry across SQLite callback exception translation."""
    if DEADLINE_EXPIRED or (RUN_DEADLINE is not None and time.monotonic() >= RUN_DEADLINE):
        deadline(0,None)


def valid_dns_name(value):
    """Validate evidence-bearing DNS names without accepting control characters."""
    name = (value[:-1] if value.endswith('.') else value).lower()
    return bool(name) and len(name)<=253 and all(LABEL.fullmatch(label) for label in name.split('.'))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Prevent bearer credentials from following remote redirects."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """Reject every redirect, including same-origin redirects."""
        raise ValueError('CZDS redirect rejected')


def download_zone(url):
    """Accept only canonical download URLs for the explicit operator scope."""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != 'https' or parsed.netloc != 'czds-api.icann.org' or parsed.query or parsed.fragment:
        raise ValueError('CZDS download origin rejected')
    match = re.fullmatch(r'/czds/downloads/([a-z]+)\.zone', parsed.path)
    if not match or match[1] not in ZONES:
        raise ValueError('CZDS download zone rejected')
    return match[1]


def sync_directory(path):
    """Make a completed rename durable on its containing filesystem."""
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class LimitedReader:
    """Count compressed HTTP bytes without buffering the zone in memory."""

    def __init__(self, raw, limit=8 * GIB):
        """Keep transport accounting separate from decompressed accounting."""
        self.raw, self.limit, self.count = raw, limit, 0
        self.digest = hashlib.sha256()

    def read(self, size=-1):
        """Fail before an unbounded or over-budget transport read."""
        if size < 0:
            size = 1 << 20
        data = self.raw.read(min(size, self.limit-self.count+1))
        self.count += len(data)
        self.digest.update(data)
        if self.count > self.limit:
            raise ValueError('Compressed zone exceeds budget')
        return data


def records(raw, zone, check_budget, metadata=None):
    """Parse supported master-file grammar and emit only immediate delegations."""
    total, previous, origin, pending, depth, soa = 0, None, zone+'.', [], 0, None
    last_delegation = None
    compressed = LimitedReader(raw)
    notices = []
    notice_size = 0
    with gzip.GzipFile(fileobj=compressed) as stream:
        while True:
            line = stream.readline(65537)
            if not line:
                break
            total += len(line)
            if len(line) > 65536 or total > 64 * GIB:
                raise ValueError('Decompressed zone exceeds budget')
            decoded = line.decode('ascii')
            if ';' in decoded:
                notice = decoded.split(';',1)[1].rstrip()
                notice_size += len(notice)+1
                if notice_size > 65536:
                    raise ValueError('Zone notice metadata exceeds budget')
                notices.append(notice)
            text = decoded.split(';', 1)[0].rstrip()
            if not text.strip():
                continue
            if text.lstrip().startswith('$'):
                directive = text.split()
                if directive[0].upper() == '$ORIGIN' and len(directive) == 2 and directive[1].lower() == zone+'.':
                    origin = zone+'.'
                    continue
                if directive[0].upper() == '$TTL' and len(directive) == 2 and re.fullmatch(r'[0-9]+[smhdwSMHDW]?',directive[1]):
                    continue
                raise ValueError('Unsupported zone directive')
            if not pending:
                omitted = text[0].isspace()
            pending.extend(text.replace('(', ' ( ').replace(')', ' ) ').split())
            depth += text.count('(')-text.count(')')
            if depth < 0 or depth > 1 or len(pending) > 128:
                raise ValueError('Malformed multiline record')
            if depth:
                continue
            tokens = [part for part in pending if part not in ('(',')')]
            pending = []
            if omitted:
                if previous is None:
                    raise ValueError('Missing initial owner')
                owner = previous
            else:
                owner = tokens.pop(0).lower()
                owner = origin if owner == '@' else owner if owner.endswith('.') else owner+'.'+origin
                previous = owner
            while tokens and (tokens[0].isdigit() or tokens[0].upper() == 'IN'):
                tokens.pop(0)
            if not tokens or not re.fullmatch(r'[A-Z][A-Z0-9]*',tokens[0].upper()):
                raise ValueError('Missing record type')
            kind, arguments = tokens[0].upper(), tokens[1:]
            if not owner.endswith('.'+zone+'.') and owner != zone+'.':
                raise ValueError('Out-of-zone owner')
            if kind == 'SOA':
                if owner != zone+'.' or len(arguments) != 7 or not all(valid_dns_name(value) for value in arguments[:2]) or not all(value.isdigit() for value in arguments[2:]):
                    raise ValueError('Invalid apex SOA')
                serial = int(arguments[2])
                if soa is not None and soa != serial:
                    raise ValueError('Conflicting SOA serials')
                soa = serial
            if kind == 'NS' and owner != zone+'.':
                if len(arguments) != 1 or not valid_dns_name(arguments[0]):
                    raise ValueError('Invalid delegation')
                domain = owner[:-1]
                labels = domain.split('.')
                if len(labels) == 2 and all(LABEL.fullmatch(label) for label in labels) and domain != last_delegation:
                    last_delegation = domain
                    yield hashlib.sha256(domain.encode('ascii')).digest()
            if total % (1 << 20) < len(line):
                check_budget()
    if pending or soa is None:
        raise ValueError('Incomplete zone')
    expected = raw.headers.get('Content-Length') if hasattr(raw,'headers') else None
    if expected is not None and int(expected) != compressed.count:
        raise ValueError('Incomplete HTTP body')
    if metadata is not None:
        metadata.update({'notices':notices,'compressed_sha256':compressed.digest.hexdigest(),'compressed_bytes':compressed.count,'decompressed_bytes':total,'soa_serial':soa,'source':API+'/czds/downloads/'+zone+'.zone'})


class Store:
    """Own durable history, acquisition ledger and atomic publications."""

    def __init__(self, root, reserve_bytes=20 * GIB):
        """Configure budgets without implicitly creating a new baseline."""
        self.root, self.reserve_bytes, self.db = Path(root), reserve_bytes, None

    def check_budget(self):
        """Protect host headroom and the complete collector directory budget."""
        size = sum(path.stat().st_size for path in self.root.iterdir() if path.is_file())
        if size > STATE_LIMIT or shutil.disk_usage(self.root).free < self.reserve_bytes:
            raise ValueError('CZDS state or host free-space budget exhausted')

    def require_initialized(self):
        """Refuse automatic recovery after local observation history is lost."""
        if not (self.root/'history.sqlite').is_file() or not (self.root/'initialized').is_file():
            raise ValueError('CZDS history requires explicit initialization or restore')
        self.connect()

    def initialize(self):
        """Create an explicitly authorized empty history, never overwrite one."""
        self.root.mkdir(parents=True,exist_ok=True)
        if (self.root/'history.sqlite').exists() or (self.root/'initialized').exists():
            raise ValueError('Existing CZDS state must be restored, not initialized')
        self.connect()
        self.db.executescript('CREATE TABLE history(zone TEXT NOT NULL, hash BLOB NOT NULL, first INTEGER NOT NULL, PRIMARY KEY(zone,hash)) WITHOUT ROWID; CREATE TABLE zones(zone TEXT PRIMARY KEY, baseline INTEGER NOT NULL, checked INTEGER NOT NULL, count INTEGER NOT NULL, attempt INTEGER NOT NULL DEFAULT 0); CREATE TABLE attempts(zone TEXT PRIMARY KEY, stamp INTEGER NOT NULL);')
        self.db.execute('CREATE INDEX observations ON history(zone,hash,first) WHERE first>0')
        self.db.execute('CREATE TABLE acquisitions(zone TEXT NOT NULL, stamp INTEGER NOT NULL, metadata TEXT NOT NULL, PRIMARY KEY(zone,stamp)) WITHOUT ROWID')
        self.db.commit()
        with (self.root/'initialized').open('xb') as marker:
            marker.write(b'CZDS history initialized; restore after loss\n')
            marker.flush()
            os.fsync(marker.fileno())
        sync_directory(self.root)

    def connect(self):
        """Bound SQLite cache, database pages and temporary storage behavior."""
        self.db = sqlite3.connect(self.root/'history.sqlite')
        self.db.execute('PRAGMA journal_mode=DELETE')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('PRAGMA cache_size=-32768')
        self.db.execute('PRAGMA temp_store=MEMORY')
        page = self.db.execute('PRAGMA page_size').fetchone()[0]
        self.db.execute(f'PRAGMA max_page_count={HISTORY_LIMIT//page}')

    def close(self):
        """Release history after the collector lock is no longer needed."""
        if self.db is not None:
            self.db.close()

    def begin_attempt(self, zone, stamp):
        """Durably reserve a 24-hour interval before issuing a download."""
        row = self.db.execute('SELECT stamp FROM attempts WHERE zone=?',(zone,)).fetchone()
        if row and stamp-row[0] < 86400:
            return False
        with self.db:
            self.db.execute('INSERT INTO attempts VALUES(?,?) ON CONFLICT(zone) DO UPDATE SET stamp=excluded.stamp',(zone,stamp))
        return True

    def ingest(self, zone, raw, stamp, minimum):
        """Commit only a complete plausible stage; preserve first observation across gaps."""
        self.check_budget()
        stage_path = self.root/'stage.sqlite'
        stage_path.unlink(missing_ok=True)
        stage = sqlite3.connect(stage_path)
        try:
            stage.execute('PRAGMA journal_mode=OFF')
            stage.execute('PRAGMA cache_size=-32768')
            stage.execute(f'PRAGMA max_page_count={HISTORY_LIMIT//4096}')
            stage.execute('CREATE TABLE incoming(hash BLOB PRIMARY KEY) WITHOUT ROWID')
            batch, metadata = [], {}
            for digest in records(raw,zone,self.check_budget,metadata):
                batch.append((digest,))
                if len(batch) == 10000:
                    stage.executemany('INSERT OR IGNORE INTO incoming VALUES(?)',batch)
                    batch.clear()
            stage.executemany('INSERT OR IGNORE INTO incoming VALUES(?)',batch)
            stage.commit()
            count = stage.execute('SELECT COUNT(*) FROM incoming').fetchone()[0]
        finally:
            stage.close()
        previous = self.db.execute('SELECT baseline,checked,count FROM zones WHERE zone=?',(zone,)).fetchone()
        if count < minimum or (previous and (stamp <= previous[1] or count < previous[2]*0.90)):
            raise ValueError('Zone count/time plausibility gate failed')
        self.check_budget()
        self.db.execute('ATTACH DATABASE ? AS staging',(str(stage_path),))
        self.db.set_progress_handler(self.progress,100000)
        try:
            with self.db:
                self.db.execute('INSERT OR IGNORE INTO history SELECT ?,hash,? FROM staging.incoming',(zone,stamp if previous else 0))
                self.db.execute('INSERT INTO zones(zone,baseline,checked,count) VALUES(?,?,?,?) ON CONFLICT(zone) DO UPDATE SET checked=excluded.checked,count=excluded.count',(zone,previous[0] if previous else stamp,stamp,count))
                self.db.execute('INSERT INTO acquisitions VALUES(?,?,?)',(zone,stamp,json.dumps(metadata)))
        finally:
            self.db.set_progress_handler(None,0)
            self.db.execute('DETACH DATABASE staging')
            stage_path.unlink(missing_ok=True)

    def progress(self):
        """Interrupt long SQL operations when host storage headroom disappears."""
        try:
            ensure_deadline()
            self.check_budget()
            return 0
        except (ValueError,OSError):
            return 1

    def publish(self, output, now):
        """Regenerate immutable recent indexes from committed acquisition timestamps."""
        output.mkdir(parents=True,exist_ok=True)
        zones = self.db.execute('SELECT zone,baseline,checked FROM zones ORDER BY zone').fetchall()
        cutoff = now-WINDOW
        count = self.db.execute('SELECT COUNT(*) FROM history WHERE first>? AND first>0',(cutoff,)).fetchone()[0]
        if count > MAX_RECORDS:
            raise ValueError('Publication window exceeds record budget; retaining last good generation')
        for zone,baseline,checked in zones:
            destination, temporary = output/(zone+'.idx'),output/(zone+'.idx.next')
            digest, count = hashlib.sha256(),0
            try:
                with temporary.open('wb') as index:
                    index.write(bytes(HEADER.size))
                    for key,first in self.db.execute('SELECT hash,first FROM history INDEXED BY observations WHERE zone=? AND first>? AND first>0 ORDER BY hash',(zone,cutoff)):
                        record = key+struct.pack('>Q',first)
                        index.write(record)
                        digest.update(record)
                        count += 1
                    index.seek(0)
                    index.write(HEADER.pack(b'CZDSIDX1',checked,baseline,count,zone.encode(),digest.digest(),bytes(48)))
                    index.flush()
                    os.fsync(index.fileno())
                os.chmod(temporary,0o644)
                os.replace(temporary,destination)
                sync_directory(output)
            finally:
                temporary.unlink(missing_ok=True)


class Client:
    """Use fixed ICANN HTTPS origins with bounded, non-logging authentication."""

    def __init__(self, credentials):
        """Read existing credentials from mounted secret files only."""
        self.username = (credentials/'username').read_text().strip()
        self.password = (credentials/'password').read_text().rstrip('\n')
        self.token = None
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())

    def authenticate(self):
        """Keep the short-lived bearer token in process memory."""
        data = json.dumps({'username':self.username,'password':self.password}).encode()
        request = urllib.request.Request(AUTH,data=data,headers={'Content-Type':'application/json'})
        with self.opener.open(request,timeout=60) as response:
            result = response.read((1<<20)+1)
        if len(result) > 1<<20:
            raise ValueError('Authentication response exceeds budget')
        token = json.loads(result).get('accessToken')
        if not isinstance(token,str) or not token or len(token)>32768:
            raise ValueError('Invalid ICANN token response')
        self.token = token

    @contextmanager
    def get(self, url):
        """Issue a single authorized request; never retry a zone download."""
        if url != API+'/czds/downloads/links':
            download_zone(url)
        request = urllib.request.Request(url,headers={'Authorization':'Bearer '+self.token})
        with self.opener.open(request,timeout=60) as response:
            if response.status != 200:
                raise ValueError('ICANN HTTP status rejected')
            yield response

    def links(self):
        """Select only approved in-scope downloads without silently choosing all."""
        with self.get(API+'/czds/downloads/links') as response:
            data = response.read((1<<20)+1)
        if len(data)>1<<20:
            raise ValueError('Download link response exceeds budget')
        links = json.loads(data)
        if not isinstance(links,list) or len(links)>2000:
            raise ValueError('Invalid download link list')
        selected = {}
        for link in links:
            if not isinstance(link,str):
                raise ValueError('Invalid download URL type')
            try:
                zone = download_zone(link)
            except ValueError:
                continue
            if zone in selected:
                raise ValueError('Duplicate zone download link')
            selected[zone] = link
        return selected


def deadline(signum, frame):
    """Bound wall-clock work even when an input stream keeps producing data."""
    global DEADLINE_EXPIRED
    DEADLINE_EXPIRED = True
    raise CollectorDeadline('CZDS run deadline reached')


def main():
    """Recover committed publications before acquiring any newly approved zones."""
    global RUN_DEADLINE, DEADLINE_EXPIRED
    RUN_DEADLINE, DEADLINE_EXPIRED = time.monotonic()+6*3600,False
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--credentials',type=Path)
    parser.add_argument('--minimum-counts',type=Path)
    parser.add_argument('--initialize',action='store_true')
    parser.add_argument('--publish-only',action='store_true')
    args = parser.parse_args()
    signal.signal(signal.SIGALRM,deadline)
    signal.alarm(6*3600)
    args.state.mkdir(parents=True,exist_ok=True)
    with (args.state/'collector.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        store = Store(args.state)
        try:
            if args.initialize:
                store.initialize()
            else:
                store.require_initialized()
            store.publish(args.output,int(time.time()))
            if args.initialize or args.publish_only:
                return
            if args.credentials is None or args.minimum_counts is None:
                raise ValueError('Credentials and reviewed baseline thresholds are required')
            minima = json.loads(args.minimum_counts.read_text())
            if set(minima) != set(ZONES) or any(type(v) is not int or v<1000 for v in minima.values()):
                raise ValueError('Explicit reviewed thresholds for all ten zones are required')
            client = Client(args.credentials)
            client.authenticate()
            links = client.links()
            print(json.dumps({'event':'czds_approval_status','available':sorted(links),'pending':sorted(set(ZONES)-set(links))}),flush=True)
            failures = 0
            for zone,url in sorted(links.items()):
                ensure_deadline()
                if not store.begin_attempt(zone,int(time.time())):
                    continue
                try:
                    with client.get(url) as response:
                        store.ingest(zone,response,int(time.time()),minimum=minima[zone])
                    store.publish(args.output,int(time.time()))
                    print(json.dumps({'event':'czds_import_completed','zone':zone}),flush=True)
                except Exception:
                    ensure_deadline()
                    failures += 1
                    print(json.dumps({'event':'czds_import_failed','zone':zone,'detail':'last committed evidence retained; next attempt no earlier than 24 hours'}),flush=True)
            if failures:
                raise ValueError('One or more CZDS imports failed')
        finally:
            store.close()


if __name__ == '__main__':
    try:
        main()
    except (Exception,CollectorDeadline):
        sys.exit('CZDS collector failed; credential values and response bodies are never logged')
