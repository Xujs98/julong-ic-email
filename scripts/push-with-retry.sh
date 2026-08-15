#!/usr/bin/env bash
set -u

remote=${1:-origin}
branch=${2:-$(git branch --show-current)}
max_attempts=4
attempt=1

if [[ -z "$branch" ]]; then
  printf '未检测到当前 Git 分支\n' >&2
  exit 2
fi

while (( attempt <= max_attempts )); do
  printf 'GitHub push attempt %d/%d: %s %s\n' "$attempt" "$max_attempts" "$remote" "$branch"
  if GIT_TERMINAL_PROMPT=0 git push --set-upstream "$remote" "$branch"; then
    printf 'GitHub push succeeded on attempt %d\n' "$attempt"
    exit 0
  fi
  if (( attempt == max_attempts )); then
    printf 'GitHub push failed after the initial attempt and three retries\n' >&2
    exit 1
  fi
  sleep $(( attempt * 2 ))
  ((attempt++))
done
