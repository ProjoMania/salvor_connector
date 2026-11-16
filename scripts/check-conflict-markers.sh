#!/bin/sh
# Fails when any tracked file (or a given ref) contains a merge-conflict marker line.
# Usage: scripts/check-conflict-markers.sh [<ref>]   (no ref: the working tree)
# Use as .git/hooks/pre-push:  exec scripts/check-conflict-markers.sh HEAD
if [ -n "$1" ]; then
    hits=$(git grep -nIE '^(<<<<<<<|=======|>>>>>>>)( |$)' "$1" -- . ':!scripts/check-conflict-markers.sh')
else
    hits=$(git grep -nIE '^(<<<<<<<|=======|>>>>>>>)( |$)' -- . ':!scripts/check-conflict-markers.sh')
fi
if [ -n "$hits" ]; then
    echo "merge-conflict markers found:" >&2
    echo "$hits" >&2
    exit 1
fi
echo "no merge-conflict markers"
