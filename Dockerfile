####################################################
# GOLANG BUILDER
####################################################
FROM golang:1.25-bookworm AS go_builder

COPY . /build/nsrl/
WORKDIR /build/nsrl

# Pure Go (modernc.org/sqlite is a pure-Go SQLite driver) -> static binary so
# it runs on the musl-based runtime below.
RUN CGO_ENABLED=0 go build -buildvcs=false -ldflags "-s -w -X main.Version=v$(cat VERSION) -X main.BuildTime=$(date -u +%Y%m%d)" -o /bin/nsrl .

####################################################
# NSRL RUNTIME
####################################################
FROM alpine:3.22

LABEL maintainer="https://github.com/blacktop"

LABEL malice.plugin.repository="https://github.com/malice-plugins/nsrl.git"
LABEL malice.plugin.category="intel"
LABEL malice.plugin.mime="hash"
LABEL malice.plugin.docker.engine="*"

# The RDSv3 SQLite database is fetched at build time, its SHA-1 is verified
# against NIST's published signature, the .db is extracted to /nsrl/RDS.db,
# and the zip is removed so it does not bloat the layer.
#
# Default: the NIST RDSv3 curated demonstration set (the smallest real RDSv3
# SQLite DB). The 18 GB RDS_2026.03.1_modern_minimal does not fit the build
# host, so it is not bundled by default. Override NSRL_DB_URL / NSRL_DB_SHA1 /
# NSRL_DB_FILE to bundle a different set (e.g. modern_minimal on a larger host).
ARG NSRL_DB_URL=https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/rds_2021.12.2/RDS_2021.12.2_curated.zip
ARG NSRL_DB_SHA1=3f2c1f015f8f7dc85e5feda56b1feae88bc323cb
ARG NSRL_DB_FILE=RDS_2021.12.2_curated.db

# /malware is the read-only sample mount point (malice volume -> /malware:ro).
# The lookup is hash-based and never reads the sample, but the core mounts it
# regardless, so the path must exist. /nsrl holds the RDSv3 database.
RUN apk add --no-cache ca-certificates su-exec curl unzip \
  && addgroup -S malice \
  && adduser -S -G malice -s /bin/sh malice \
  && mkdir -p /nsrl /malware \
  && chown -R malice:malice /nsrl /malware \
  && curl -fsSL --retry 3 -o /tmp/nsrl.zip "$NSRL_DB_URL" \
  && unzip -j -o /tmp/nsrl.zip "$NSRL_DB_FILE" -d /nsrl/ \
  && echo "$NSRL_DB_SHA1  /nsrl/$NSRL_DB_FILE" | sha1sum -c - \
  && mv /nsrl/$NSRL_DB_FILE /nsrl/RDS.db \
  && chown malice:malice /nsrl/RDS.db \
  && rm -f /tmp/nsrl.zip

COPY --from=go_builder /bin/nsrl /bin/nsrl

WORKDIR /malware

ENTRYPOINT ["su-exec","malice","nsrl"]
CMD ["--help"]

####################################################
####################################################
