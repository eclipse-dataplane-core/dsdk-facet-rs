#!/usr/bin/env bash
# Runs the Eclipse Dash License Tool over the workspace's normal (non-dev) dependencies.
# Writes DEPENDENCIES.txt and fails if any dependency is restricted or rejected, i.e. still needs
# an Eclipse IP Team review (see scripts/request-dependency-review.sh to file those reviews).
#
# Usage: scripts/check-dependencies.sh
# Environment: see scripts/dash-common.sh (DASH_JAR, DASH_TIMEOUT).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
# shellcheck source=scripts/dash-common.sh
source scripts/dash-common.sh

SUMMARY=DEPENDENCIES.txt

dash_ensure_jar

# Dash writes the summary incrementally, so write to a temp file and only replace the committed
# summary once the tool ran to completion (exit 127 = internal error, e.g. a network timeout).
tmp_summary=$(mktemp)
trap 'rm -f "$tmp_summary"' EXIT
status=0
dash_dependency_ids | java -jar "$DASH_JAR" -batch 50 -timeout "$DASH_TIMEOUT" -summary "$tmp_summary" - || status=$?

if [ "$status" -eq 127 ]; then
  echo "::error::Eclipse Dash License Tool failed to run; $SUMMARY was left unchanged."
  exit "$status"
fi
mv "$tmp_summary" "$SUMMARY"

# Explicit gate on the summary (dash itself already exits non-zero for non-approved content).
if grep -E ', (restricted|rejected), ' "$SUMMARY"; then
  echo "::error::Restricted or rejected dependencies found in $SUMMARY (see above). File an IP review before releasing."
  exit 1
fi
exit "$status"
