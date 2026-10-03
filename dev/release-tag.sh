#!/usr/bin/env bash
# Create the release tag for the version in pyproject.toml.
#
# The tag name is derived, never typed, so it cannot be malformed. The tag
# is created locally only; pushing it (which triggers the GHCR publish
# workflow) stays a manual step.
#
# Refuses unless:
#   * the current branch is main and the working tree is clean,
#   * HEAD equals origin/main (the release commit is pushed and any
#     sync-prod-requirements bot commit is pulled),
#   * CHANGELOG.md has a section for the version,
#   * the tag does not already exist, locally or on origin.
#
# Usage:
#   dev/release-tag.sh        (or: make release-tag)

set -euo pipefail

cd "$(dirname "$0")/.."

die() {
  echo "release-tag: $*" >&2
  exit 1
}

VERSION=$(python3 -c "
import tomllib
with open('pyproject.toml', 'rb') as f:
    print(tomllib.load(f)['tool']['poetry']['version'])
")
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
  || die "pyproject.toml version '$VERSION' is not MAJOR.MINOR.PATCH"
TAG="v$VERSION"

BRANCH=$(git rev-parse --abbrev-ref HEAD)
[ "$BRANCH" = "main" ] || die "on branch '$BRANCH', releases are tagged on main"

[ -z "$(git status --porcelain)" ] || die "working tree is not clean"

grep -qE "^## \[$VERSION\]" CHANGELOG.md \
  || die "CHANGELOG.md has no section for $VERSION"

git fetch --quiet --tags origin main
HEAD_SHA=$(git rev-parse HEAD)
[ "$HEAD_SHA" = "$(git rev-parse origin/main)" ] \
  || die "HEAD differs from origin/main. Push main, wait for sync-prod-requirements, then pull"

if git ls-remote --exit-code --tags origin "refs/tags/$TAG" >/dev/null 2>&1; then
  die "$TAG already exists on origin"
fi

if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
  [ "$(git rev-parse "$TAG^{commit}")" = "$HEAD_SHA" ] \
    || die "$TAG already exists locally on another commit. Delete it with: git tag -d $TAG"
  echo "$TAG already exists on HEAD ($(git rev-parse --short HEAD))."
else
  git tag "$TAG"
  echo "Created $TAG on $(git rev-parse --short HEAD)."
fi

echo "Publish the release with:"
echo "  git push origin $TAG"
