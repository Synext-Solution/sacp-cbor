#!/usr/bin/env bash
set -euo pipefail

package_meta() {
  MANIFEST="$1" python3 -c 'import os, pathlib, tomllib; data=tomllib.loads(pathlib.Path(os.environ["MANIFEST"]).read_text()); pkg=data.get("package", {}); name=pkg.get("name"); version=pkg.get("version"); print("MISSING" if not name or not version else f"{name} {version}")'
}

dependency_version() {
  MANIFEST="$1" DEP="$2" python3 -c 'import os, pathlib, tomllib; data=tomllib.loads(pathlib.Path(os.environ["MANIFEST"]).read_text()); print(data["dependencies"][os.environ["DEP"]]["version"])'
}

require_exact_dependency() {
  local manifest="$1"
  local dependency="$2"
  local expected="$3"
  local declared
  declared="$(dependency_version "$manifest" "$dependency")"
  if [[ "$declared" != "=${expected}" ]]; then
    echo "${manifest}: ${dependency} must be declared as =${expected}, found ${declared}." >&2
    exit 1
  fi
}

require_meta() {
  local manifest="$1"
  local expected_name="$2"
  local meta
  meta="$(package_meta "$manifest")"
  if [[ "$meta" == "MISSING" || -z "$meta" ]]; then
    echo "Failed to parse package metadata from ${manifest}." >&2
    exit 1
  fi
  if [[ "${meta%% *}" != "$expected_name" ]]; then
    echo "Unexpected package name in ${manifest}: ${meta%% *}." >&2
    exit 1
  fi
  printf '%s\n' "${meta#* }"
}

require_readme_line() {
  local crate="$1"
  local release_line="$2"
  shift 2
  local stale
  stale="$(grep -hoE "${crate} = (\\{ )?(version = )?\"[0-9]+\\.[0-9]+(\\.[0-9]+)?\"" "$@" | grep -oE '"[0-9.]+"' | tr -d '"' | grep -vx "$release_line" || true)"
  if [[ -n "$stale" ]]; then
    echo "README references stale ${crate} version(s): ${stale} (current line ${release_line})." >&2
    exit 1
  fi
}

is_published() {
  CRATE="$1" VERSION="$2" python3 -c $'import json, os, sys, urllib.request, urllib.error\ncrate=os.environ["CRATE"]\nversion=os.environ["VERSION"]\nurl=f"https://crates.io/api/v1/crates/{crate}"\ntry:\n    with urllib.request.urlopen(url, timeout=10) as response:\n        data=json.load(response)\nexcept urllib.error.HTTPError as error:\n    if error.code == 404:\n        sys.exit(1)\n    print(f"Failed to query crates.io: {error}", file=sys.stderr)\n    sys.exit(2)\nexcept Exception as error:\n    print(f"Failed to query crates.io: {error}", file=sys.stderr)\n    sys.exit(2)\nversions={entry.get("num") for entry in data.get("versions", [])}\nsys.exit(0 if version in versions else 1)\n'
}

wait_for_published() {
  local crate="$1"
  local version="$2"
  local attempt
  for attempt in $(seq 1 30); do
    if is_published "$crate" "$version" && cargo info "${crate}@${version}" >/dev/null 2>&1; then
      return 0
    fi
    echo "Waiting for ${crate} ${version} to appear on crates.io (${attempt}/30)."
    sleep 10
  done
  echo "${crate} ${version} did not appear on crates.io in time." >&2
  return 1
}

publish_crate() {
  local crate="$1"
  local version="$2"
  local package="$3"
  local published
  set +e
  is_published "$crate" "$version"
  published=$?
  set -e
  if [[ "$published" -gt 1 ]]; then
    exit 1
  fi
  if [[ "$published" -eq 0 ]]; then
    echo "${crate} ${version} is already on crates.io; skipping."
    return 0
  fi
  if [[ -z "${CARGO_REGISTRY_TOKEN:-}" ]]; then
    echo "CARGO_REGISTRY_TOKEN is not set; cannot publish ${crate} ${version}." >&2
    exit 1
  fi
  cargo publish -p "$package" --locked
  wait_for_published "$crate" "$version"
}

release_tag_object_type() {
  git cat-file -t "refs/tags/$1"
}

release_tag_commit() {
  git rev-list -n 1 "$1"
}

validate_existing_tag_state() {
  local tag="$1"
  local head_commit="$2"
  shift 2
  local release crate version _package published
  if [[ "$(release_tag_object_type "$tag")" != "tag" ]]; then
    echo "Existing ${tag} is not an annotated tag." >&2
    exit 1
  fi
  if [[ "$(release_tag_commit "$tag")" != "$head_commit" ]]; then
    echo "Existing ${tag} does not point at the release commit." >&2
    exit 1
  fi
  for release in "$@"; do
    read -r crate version _package <<<"$release"
    set +e
    is_published "$crate" "$version"
    published=$?
    set -e
    if [[ "$published" -ne 0 ]]; then
      echo "Existing ${tag} cannot be recovered: ${crate} ${version} is not confirmed published." >&2
      exit 1
    fi
  done
}

main() {
if [[ "${GITHUB_EVENT_NAME:-}" != "workflow_dispatch" ]]; then
  echo "Releases are allowed only from workflow_dispatch." >&2
  exit 1
fi
if [[ "${GITHUB_REF:-}" != "refs/heads/${DEFAULT_BRANCH:?}" ]]; then
  echo "Releases must be dispatched from ${DEFAULT_BRANCH}." >&2
  exit 1
fi
git fetch --quiet origin "$DEFAULT_BRANCH" --tags
head_commit="$(git rev-parse HEAD)"
remote_commit="$(git rev-parse "origin/${DEFAULT_BRANCH}")"
if [[ "$head_commit" != "$remote_commit" ]]; then
  echo "Release checkout is not the current origin/${DEFAULT_BRANCH}." >&2
  exit 1
fi
if [[ -n "$(git status --porcelain)" ]]; then
  echo "Release checkout is dirty." >&2
  exit 1
fi

root_version="$(require_meta Cargo.toml sacp-cbor)"
derive_version="$(require_meta sacp-cbor-derive/Cargo.toml sacp-cbor-derive)"
schema_version="$(require_meta sacp-cbor-schema/Cargo.toml sacp-cbor-schema)"
abi_derive_version="$(require_meta sacp-cbor-abi-derive/Cargo.toml sacp-cbor-abi-derive)"
abi_version="$(require_meta sacp-cbor-abi/Cargo.toml sacp-cbor-abi)"

if [[ "$RELEASE_VERSION" != "$root_version" ]]; then
  echo "Requested version ${RELEASE_VERSION} does not match sacp-cbor ${root_version}." >&2
  exit 1
fi
if [[ "$derive_version" != "$root_version" ]]; then
  echo "sacp-cbor-derive ${derive_version} does not match sacp-cbor ${root_version}." >&2
  exit 1
fi
require_exact_dependency Cargo.toml sacp-cbor-derive "$derive_version"
require_exact_dependency sacp-cbor-schema/Cargo.toml sacp-cbor "$root_version"
require_exact_dependency sacp-cbor-abi/Cargo.toml sacp-cbor "$root_version"
require_exact_dependency sacp-cbor-abi/Cargo.toml sacp-cbor-abi-derive "$abi_derive_version"

require_readme_line sacp-cbor "${root_version%.*}" README.md sacp-cbor-abi/README.md
require_readme_line sacp-cbor-schema "${schema_version%.*}" README.md sacp-cbor-schema/README.md
require_readme_line sacp-cbor-abi "${abi_version%.*}" README.md sacp-cbor-abi/README.md

local -a releases=(
  "sacp-cbor-derive ${derive_version} sacp-cbor-derive"
  "sacp-cbor ${root_version} sacp-cbor"
  "sacp-cbor-schema ${schema_version} sacp-cbor-schema"
  "sacp-cbor-abi-derive ${abi_derive_version} sacp-cbor-abi-derive"
  "sacp-cbor-abi ${abi_version} sacp-cbor-abi"
)

for release in "${releases[@]}"; do
  read -r crate version _package <<<"$release"
  if ! grep -Fq -- "- \`${crate}\` ${version}" CHANGELOG.md; then
    echo "CHANGELOG.md does not declare ${crate} ${version}." >&2
    exit 1
  fi
done

if [[ "${1:-}" == "--metadata-only" ]]; then
  echo "release metadata preflight passed"
  exit 0
fi

tag="v${root_version}"
tag_exists=0
if git rev-parse -q --verify "refs/tags/${tag}" >/dev/null; then
  tag_exists=1
  validate_existing_tag_state "$tag" "$head_commit" "${releases[@]}"
fi

for release in "${releases[@]}"; do
  read -r crate version package <<<"$release"
  publish_crate "$crate" "$version" "$package"
done

# A tag is the final release marker. Never create it until every registry object is observable.
for release in "${releases[@]}"; do
  read -r crate version _package <<<"$release"
  if ! is_published "$crate" "$version"; then
    echo "Refusing to tag: ${crate} ${version} is not observable on crates.io." >&2
    exit 1
  fi
done

if [[ "$tag_exists" -eq 0 ]]; then
  git config user.name "github-actions[bot]"
  git config user.email "github-actions[bot]@users.noreply.github.com"
  git tag -a "$tag" -m "Release ${tag}" "$head_commit"
  git push origin "refs/tags/${tag}"
else
  echo "Annotated tag ${tag} already marks this release commit."
fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
