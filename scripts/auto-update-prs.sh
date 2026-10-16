#!/usr/bin/env bash
# Update every open same-repository PR with auto-merge enabled to the latest
# main, through the update-branch API. Used by .github/workflows/auto-update.yml.
#
#   GH_TOKEN=... scripts/auto-update-prs.sh owner/repo
#
# On a conflict: label "needs-rebase" and comment once.
# On success: remove "needs-rebase" and dispatch CI on the branch.
# Environment: DRY_RUN=1 prints what would happen without changing anything.
set -euo pipefail

repo=${1:?usage: $0 owner/repo}
label=needs-rebase
dry=${DRY_RUN:-0}

run() {
  if [ "$dry" = 1 ]; then echo "DRY RUN: $*"; else "$@"; fi
}

if [ "$dry" != 1 ]; then
  gh label create "$label" -R "$repo" --color B60205 \
    --description "Conflicts with main; rebase needed (set by the auto-update workflow)" >/dev/null 2>&1 || true
fi

prs=$(gh pr list -R "$repo" --state open --limit 200 \
  --json number,headRefName,headRefOid,isCrossRepository,autoMergeRequest,labels \
  --jq '.[] | select(.autoMergeRequest != null and (.isCrossRepository | not))
        | [.number, .headRefName, .headRefOid, ([.labels[].name] | index("'"$label"'") != null)] | @tsv')

if [ -z "$prs" ]; then
  echo "auto-update: no open PRs with auto-merge enabled"
  exit 0
fi

while IFS=$'\t' read -r num ref sha labeled; do
  echo "auto-update: PR #$num ($ref @ ${sha:0:12})"
  if [ "$dry" = 1 ]; then
    echo "DRY RUN: gh api -X PUT repos/$repo/pulls/$num/update-branch -f expected_head_sha=$sha"
    continue
  fi
  if out=$(gh api -X PUT "repos/$repo/pulls/$num/update-branch" -f expected_head_sha="$sha" 2>&1); then
    echo "  updated: $out"
    if [ "$labeled" = true ]; then
      run gh pr edit "$num" -R "$repo" --remove-label "$label" >/dev/null || true
    fi
    run gh workflow run ci.yml -R "$repo" --ref "$ref" || echo "  could not dispatch CI on $ref"
    continue
  fi
  case "$out" in
    *"no new commits"*|*"is already up to date"*)
      echo "  already up to date"
      ;;
    *"expected head sha"*|*"expected_head_sha"*)
      echo "  head moved during the update; the next push to main retries"
      ;;
    *onflict*)
      echo "  conflicts with main"
      if [ "$labeled" != true ]; then
        run gh pr edit "$num" -R "$repo" --add-label "$label" >/dev/null || true
        run gh pr comment "$num" -R "$repo" --body "This branch conflicts with main and could not be updated automatically. Rebase it onto main (or run scripts/merge-queue.sh $num, which regenerates generated files and unions CHANGELOG.md), then push. The auto-update workflow removes the $label label after the next successful update." >/dev/null || true
      fi
      ;;
    *)
      echo "  update failed: $out"
      ;;
  esac
done <<<"$prs"
