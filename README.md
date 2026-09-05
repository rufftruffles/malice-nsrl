# malice/nsrl

Malice plugin for [NSRL](https://www.nsrl.nist.gov/) (NIST National Software
Reference Library) hash lookups.

The engine looks a file's SHA1 (or MD5) up in the NIST RDSv3 (Reference Data
Set v3) SQLite database and records the result in Elasticsearch under
`plugins.intel.nsrl`. A hash present in the NSRL is a known-legitimate software
file (whitelisted); a hash absent from the NSRL is not a known-good file and is
left for the other engines to analyze.

## Modernization notes (vs. the old plugin)

- Exact lookup, not a Bloom filter. The old plugin built a probabilistic Bloom
  filter from the RDS 2.XX CSV (`NSRLFile.txt`) with a 0.1% false-positive
  rate. This engine performs an exact `SELECT ... FROM FILE WHERE sha1 = ?`
  against the authoritative RDSv3 SQLite database.
- RDSv3 format. NIST has retired the RDS 2.XX text files and publishes only
  RDSv3 SQLite databases. The RDSv3 `FILE` view/table exposes
  `(sha256, sha1, md5, file_name, file_size, package_id)` with hashes
  upper-cased; the engine queries both cases to be robust across publications.
- ES 8 client via the shared `malice-plugins/pkgs` (go-elasticsearch/v8).

## The database

The full RDSv3 2026.03.1 `modern_minimal` set is 18 GB (the zip alone), so it
needs a large build host. This image bundles the NIST RDSv3 curated
demonstration set instead: `RDS_2021.12.2_curated`, 292 MB `.db` (677,723
files, 408,811 distinct SHA-256), the smallest real RDSv3 SQLite DB, fetched
and SHA-1-verified at build time.

The database path is configurable via the `NSRL_DB` env var (default
`/nsrl/RDS.db`). To use the full modern whitelist, build with the larger set:

```
docker build \
  --build-arg NSRL_DB_URL=https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/rds_2026.03.1/RDS_2026.03.1_modern_minimal.zip \
  --build-arg NSRL_DB_SHA1=<sha1 from NIST signatures.txt for the release> \
  --build-arg NSRL_DB_FILE=RDS_2026.03.1_modern_minimal.db \
  -t malice/nsrl:latest .
```

(Requires a build host with >~20 GB free. No code change is needed, only the
build args.)

## Usage

```
docker run --rm -e MALICE_SCANID=<id> -e MALICE_ELASTICSEARCH_URL=http://172.17.0.1:9200 \
  malice/nsrl:latest lookup -t <sha1>
```

The engine writes `plugins.intel.nsrl`:

```json
{ "found": true, "hash": "39A6D01274827FE2B33DCD508EE2EB2342061B55",
  "sha256": "0F04A4EB...", "md5": "C64B5A3C...", "file_name": "...", "file_size": 8468 }
```

or, for a hash not in the NSRL: `{ "found": false, "hash": "..." }`. Every
failure path (missing DB, open error, query error) writes a valid document with
`found: false` and an `error` field; the engine never crashes a scan.

## Build

```
make build && make tag
```

## License

MIT (see LICENSE).
