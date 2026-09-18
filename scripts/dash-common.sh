#!/usr/bin/env bash
# Shared helpers for the Eclipse Dash License Tool (https://github.com/eclipse-dash/dash-licenses).
# Source this file; it expects `set -euo pipefail` and the repo root as working directory.
#
#   DASH_JAR=/path/to/dash.jar   reuse an already downloaded jar (default: $RUNNER_TEMP or /tmp)
#   DASH_TIMEOUT=120             per-request timeout in seconds for the license services

DASH_JAR="${DASH_JAR:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/dash.jar}"
DASH_URL='https://repo.eclipse.org/service/rest/v1/search/assets/download?sort=version&repository=dash-maven2-releases&maven.groupId=org.eclipse.dash&maven.artifactId=org.eclipse.dash.licenses&maven.extension=jar'
DASH_TIMEOUT="${DASH_TIMEOUT:-120}"

# Eclipse project this repository belongs to (https://projects.eclipse.org/projects/technology.dataplane-core).
ECLIPSE_PROJECT_ID="${ECLIPSE_PROJECT_ID:-technology.dataplane-core}"
ECLIPSE_PROJECT_REPO="${ECLIPSE_PROJECT_REPO:-https://github.com/eclipse-dataplane-core/dsdk-facet-rs}"

# Downloads the latest released dash jar unless DASH_JAR already exists.
dash_ensure_jar() {
  if [ ! -f "$DASH_JAR" ]; then
    echo "Downloading Eclipse Dash License Tool to $DASH_JAR" >&2
    curl -sSfL -o "$DASH_JAR" "$DASH_URL"
  fi
}

# Prints the ClearlyDefined ids ("crate/cratesio/-/<name>/<version>") of all normal (non-dev)
# dependencies from the committed Cargo.lock, one per line.
#
# cargo tree lines look like: "name v1.2.3", "name v1.2.3 (proc-macro)", "name v1.2.3 (/local/path)",
# "name v1.2.3 (https://git...)". Only registry crates have a ClearlyDefined id on crates.io; local
# path crates (the workspace members) and git sources are dropped. Blank lines separate workspace roots.
dash_dependency_ids() {
  cargo tree -e normal --prefix none --no-dedupe --locked \
    | sort -u \
    | grep -v '^[[:space:]]*$' \
    | grep -Ev ' \((/|[a-z+]+://)' \
    | sed -E 's|^([^ ]+) v([^ ]+).*$|crate/cratesio/-/\1/\2|'
}
