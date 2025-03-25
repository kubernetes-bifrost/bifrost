#!/bin/bash

# MIT License
#
# Copyright (c) 2025 kubernetes-bifrost
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

set -e

new_version=$1

# Parse the version as semver.
if [[ ! $new_version =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Invalid version format. Please provide version in format v0.0.0"
    exit 1
fi

# Check if there are uncommitted changes.
if [ $(git status --porcelain=v1 2>/dev/null | wc -l) -ne 0 ]; then
    echo "There are uncommitted changes. Please commit or stash them before bumping the versions."
    exit 1
fi

# Check if the current branch is main.
if [ "$(git branch --show-current)" != "main" ]; then
    echo "You must be on main branch to bump the versions."
    exit 1
fi

# Pull the latest changes.
git pull

# Create release branch. First, if the branch already exists, delete it.
if git show-ref --verify --quiet refs/heads/release; then
    git branch -D release
fi
git checkout -b release

# Bump the versions in go.mod files.
for f in `find . -wholename \*go.mod`; do
    tmp_f=$(mktemp)
    changed=""
    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ $line =~ github\.com/kubernetes-bifrost/bifrost.*\ v.* ]]; then
            pkg=$(echo $line | awk '{print $1}')
            echo -e "\t$pkg $new_version" >> $tmp_f
            changed="true"
        else
            echo "$line" >> $tmp_f
        fi
    done < "$f"
    if [ "$changed" == "true" ]; then
        mv $tmp_f $f
    else
        rm -f $tmp_f
    fi
done

# If there are no changes, exit.
if git --no-pager diff --exit-code; then
    exit 0
fi

# Prompt for confirmation.
echo ""
echo "Some versions were upgraded. Proceed with release? y/n"
echo ""
read -r input

# If the user did not confirm, exit.
if [ "$input" != "y" ]; then
    echo "Aborting release."
    exit 0
fi

# Proceed with the release.
git add .
git commit -asm "Release $new_version"
git push --set-upstream origin release
gh pr create --base main --head release --fill-verbose
echo ""

# Now wait on a loop until the PR is merged.
while true; do
    pr_status=$(gh pr view --json state --jq '.state')
    if [ "$pr_status" == "MERGED" ]; then
        break
    fi
    echo "PR not merged yet. Waiting for 30 seconds."
    sleep 30
done

# Checkout main branch, pull and cleanup.
git checkout main
git pull
git fetch --prune --all --force --tags
git branch -d release

# Tag main gRPC service and providers
git tag -s -m grpc/bifrost/go/$new_version grpc/bifrost/go/$new_version
for path in providers/*; do
    provider=$(basename $path)
    tags=(
        "providers/$provider/$new_version"
        "grpc/$provider/go/$new_version"
    )
    for tag in "${tags[@]}"; do
        git tag -s -m $tag $tag
    done
done
git push origin --tags

# Tag main module.
git tag -s -m $new_version $new_version
git push origin $new_version
