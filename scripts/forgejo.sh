#!/bin/sh
# Forgejo helpers: open a PR, wait for CI. (Same script as feather-tester-software.)
#
#   forgejo.sh pr <title> <body-file>   push HEAD's branch, open a PR against
#                                       the default branch, print its URL
#   forgejo.sh ci [<commit>|<tag>]      wait for CI on the commit (default
#                                       HEAD), print each job, fail if any did;
#                                       for a tag, the tag's own run only
#
# The token is FORGEJO_TOKEN from the environment or from the main checkout's
# .env (found through git's common dir, so this works from a worktree too).
# It needs read:repository and write:repository.
set -eu

die() { echo "$*" >&2; exit 1; }

origin="$(git remote get-url origin)"
host="$(printf '%s\n' "$origin" | sed -E 's#^https://([^/]+)/.*#\1#')"
slug="$(printf '%s\n' "$origin" | sed -E 's#^https://[^/]+/##; s#\.git$##')"
case "$origin" in https://*) ;; *) die "origin is not an https remote: $origin" ;; esac
api="https://$host/api/v1/repos/$slug"

token="${FORGEJO_TOKEN:-}"
if [ -z "$token" ]; then
    env_file="$(git rev-parse --path-format=absolute --git-common-dir)/../.env"
    [ -f "$env_file" ] && token="$(sed -n 's/^\(export \)\{0,1\}FORGEJO_TOKEN=//p' "$env_file" | tr -d '"' | tail -1)"
fi
[ -n "$token" ] || die "FORGEJO_TOKEN is not set and not in the main checkout's .env"

call() { # METHOD PATH [JSON]
    if [ $# -ge 3 ]; then
        curl -sS --fail-with-body -X "$1" -H "Authorization: token $token" \
            -H 'Content-Type: application/json' -d "$3" "$api$2"
    else
        curl -sS --fail-with-body -X "$1" -H "Authorization: token $token" "$api$2"
    fi
}

case "${1:-}" in
pr)
    [ $# -eq 3 ] || die "usage: forgejo.sh pr <title> <body-file>"
    [ -f "$3" ] || die "no such body file: $3"
    branch="$(git symbolic-ref --short HEAD)" || die "HEAD is detached"
    base="$(call GET "" | jq -r .default_branch)"
    [ "$branch" != "$base" ] || die "on $base — open PRs from a feature branch"
    git push -u origin "$branch"
    existing="$(call GET "/pulls?state=open&limit=50" \
        | jq -r --arg b "$branch" '.[] | select(.head.label == $b or .head.ref == $b) | .html_url' | head -1)"
    if [ -n "$existing" ]; then
        echo "PR already open: $existing"
        exit 0
    fi
    body="$(jq -n --arg h "$branch" --arg b "$base" --arg t "$2" --rawfile d "$3" \
        '{head: $h, base: $b, title: $t, body: $d}')"
    call POST /pulls "$body" | jq -r '"opened #\(.number): \(.html_url)"'
    ;;
ci)
    ref="${2:-HEAD}"
    sha="$(git rev-parse --verify "$ref^{commit}")"
    # A release commit is built twice: by the main push and by its tag's
    # push, same sha and event. Only the tag's run publishes, so for a tag
    # wait on that run alone rather than passing on the main run.
    tag=""
    if git show-ref --verify --quiet "refs/tags/$ref"; then
        tag="$ref"
    fi
    echo "waiting for CI on ${tag:-${sha%"${sha#???????}"}} ($slug)"
    # Wait on runs, not jobs: a job only appears in /actions/tasks once a
    # runner picks it up, so a job that `needs:` another (build after
    # checks) is invisible until its dependency finishes, and a job list
    # can look complete while the run is not. A run exists from the moment
    # its event fires and carries the overall status.
    n=0
    while :; do
        # Latest attempt per trigger (event + ref; a re-run supersedes).
        runs="$(call GET "/actions/runs?limit=50" | jq -c --arg s "$sha" --arg t "$tag" '
            [.workflow_runs[] | select(.commit_sha == $s)
             | select($t == "" or .prettyref == $t)]
            | group_by(.event + "/" + .prettyref) | map(max_by(.id))')"
        total="$(printf '%s' "$runs" | jq length)"
        pending="$(printf '%s' "$runs" | jq '[.[] | select(.status | IN("waiting","running","blocked","unknown"))] | length')"
        if [ "$total" -gt 0 ] && [ "$pending" -eq 0 ]; then
            break
        fi
        n=$((n + 1))
        # No run 2 minutes after asking means no workflow fires for this
        # commit (e.g. a branch push with no PR open). A run that never
        # finishes gets an hour.
        [ "$total" -gt 0 ] || [ "$n" -lt 12 ] || die "no CI run for ${tag:-this commit} — is it pushed (with a PR open, for a branch)?"
        [ "$n" -lt 360 ] || die "CI still running after an hour"
        sleep 10
    done
    # Per-job detail for those runs (tasks carry the run's number).
    numbers="$(printf '%s' "$runs" | jq -c '[.[].index_in_repo]')"
    call GET "/actions/tasks?limit=100" | jq -r --argjson r "$numbers" '
        [.workflow_runs[] | select(.run_number as $n | $r | index($n))]
        | group_by((.run_number | tostring) + "/" + .name) | map(max_by(.id)) | .[]
        | "  \(.status)\t\(.event)\t\(.name)\t\(.url)"'
    printf '%s' "$runs" | jq -r '.[] | "run \(.prettyref) (\(.event)): \(.status)"'
    printf '%s' "$runs" | jq -e 'all(.status | IN("success","skipped"))' >/dev/null \
        || die "CI failed"
    echo "CI passed"
    ;;
*)
    die "usage: forgejo.sh pr <title> <body-file> | ci [<commit>|<tag>]"
    ;;
esac
