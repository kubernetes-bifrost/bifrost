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

# Tag main module.
git tag -s -m $new_version $new_version

# Tag providers.
for path in providers/*; do
    provider=$(basename $path)
    tag="providers/$provider/$new_version"
    git tag -s -m $tag $tag
done
