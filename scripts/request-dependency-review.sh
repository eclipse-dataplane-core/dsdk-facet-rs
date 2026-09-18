#!/usr/bin/env bash
# Files Eclipse IP Team review requests (IPLab issues on gitlab.eclipse.org) for every dependency
# that the Eclipse Dash License Tool cannot approve automatically. Run this when
# scripts/check-dependencies.sh reports restricted dependencies.
#
# Usage: GITLAB_API_TOKEN=<token> scripts/request-dependency-review.sh
#
#   GITLAB_API_TOKEN      required; a personal access token from gitlab.eclipse.org with scope `api`
#                         (https://gitlab.eclipse.org/-/user_settings/personal_access_tokens).
#                         Passed via the environment only, never as an argument. Do not share it.
#   ECLIPSE_PROJECT_ID    Eclipse project id (default: technology.dataplane-core)
#   ECLIPSE_PROJECT_REPO  repository URL attached to the review requests
#   DASH_JAR, DASH_TIMEOUT see scripts/dash-common.sh
#
# Dash files at most five review requests per run, so re-run the script until it reports nothing
# left to review. Content that already has an open review is not filed twice. The tool exits
# non-zero while any dependency is still unapproved; that is expected until the IP Team has
# closed the reviews.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
# shellcheck source=scripts/dash-common.sh
source scripts/dash-common.sh

if [ -z "${GITLAB_API_TOKEN:-}" ]; then
  echo "GITLAB_API_TOKEN is not set. Create a token with scope 'api' at" >&2
  echo "https://gitlab.eclipse.org/-/user_settings/personal_access_tokens and export it." >&2
  exit 2
fi

dash_ensure_jar

echo "Requesting IP Team reviews for project $ECLIPSE_PROJECT_ID ($ECLIPSE_PROJECT_REPO)" >&2
dash_dependency_ids \
  | java -jar "$DASH_JAR" \
      -batch 50 \
      -timeout "$DASH_TIMEOUT" \
      -review \
      -token "$GITLAB_API_TOKEN" \
      -project "$ECLIPSE_PROJECT_ID" \
      -repo "$ECLIPSE_PROJECT_REPO" \
      -
