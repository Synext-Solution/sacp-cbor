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

readonly REGISTRY_MISSING=10
readonly REGISTRY_QUERY_FAILED=13

package_archive() {
  printf 'target/package/%s-%s.crate\n' "$1" "$2"
}

verify_published_artifact() {
  local crate="$1"
  local version="$2"
  python3 scripts/check_registry_artifact.py \
    "$crate" "$version" "$(package_archive "$crate" "$version")"
}

wait_for_published() {
  local crate="$1"
  local version="$2"
  local attempt
  for attempt in $(seq 1 30); do
    local status
    if verify_published_artifact "$crate" "$version"; then
      status=0
    else
      status=$?
    fi
    if [[ "$status" -eq 0 ]]; then
      if cargo info "${crate}@${version}" >/dev/null 2>&1; then
        return 0
      fi
    elif [[ "$status" -ne "$REGISTRY_MISSING" && "$status" -ne "$REGISTRY_QUERY_FAILED" ]]; then
      return "$status"
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
  if verify_published_artifact "$crate" "$version"; then
    published=0
  else
    published=$?
  fi
  if [[ "$published" -ne 0 && "$published" -ne "$REGISTRY_MISSING" ]]; then
    return "$published"
  fi
  if [[ "$published" -eq 0 ]]; then
    echo "${crate} ${version} is already on crates.io; waiting for Cargo resolution."
    wait_for_published "$crate" "$version"
    return
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
    if verify_published_artifact "$crate" "$version"; then
      published=0
    else
      published=$?
    fi
    if [[ "$published" -ne 0 ]]; then
      echo "Existing ${tag} cannot be recovered: ${crate} ${version} is not confirmed published." >&2
      exit 1
    fi
  done
}

workspace_release_matrix() {
  local expected_root_version="$1"
  local root_version derive_version schema_version abi_derive_version abi_version
  root_version="$(require_meta Cargo.toml sacp-cbor)"
  derive_version="$(require_meta sacp-cbor-derive/Cargo.toml sacp-cbor-derive)"
  schema_version="$(require_meta sacp-cbor-schema/Cargo.toml sacp-cbor-schema)"
  abi_derive_version="$(require_meta sacp-cbor-abi-derive/Cargo.toml sacp-cbor-abi-derive)"
  abi_version="$(require_meta sacp-cbor-abi/Cargo.toml sacp-cbor-abi)"

  if [[ "$expected_root_version" != "$root_version" ]]; then
    echo "Requested version ${expected_root_version} does not match sacp-cbor ${root_version}." >&2
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

  printf '%s\n' \
    "sacp-cbor-derive ${derive_version} sacp-cbor-derive" \
    "sacp-cbor ${root_version} sacp-cbor" \
    "sacp-cbor-schema ${schema_version} sacp-cbor-schema" \
    "sacp-cbor-abi-derive ${abi_derive_version} sacp-cbor-abi-derive" \
    "sacp-cbor-abi ${abi_version} sacp-cbor-abi"
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

local release_matrix
release_matrix="$(workspace_release_matrix "$RELEASE_VERSION")"
local -a releases
mapfile -t releases <<<"$release_matrix"
root_version="${releases[1]#* }"
root_version="${root_version%% *}"
derive_version="${releases[0]#* }"
derive_version="${derive_version%% *}"
schema_version="${releases[2]#* }"
schema_version="${schema_version%% *}"
abi_derive_version="${releases[3]#* }"
abi_derive_version="${abi_derive_version%% *}"
abi_version="${releases[4]#* }"
abi_version="${abi_version%% *}"

require_readme_line sacp-cbor "${root_version%.*}" README.md sacp-cbor-abi/README.md
require_readme_line sacp-cbor-schema "${schema_version%.*}" README.md sacp-cbor-schema/README.md
require_readme_line sacp-cbor-abi "${abi_version%.*}" README.md sacp-cbor-abi/README.md

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
  if ! verify_published_artifact "$crate" "$version"; then
    echo "Refusing to tag: ${crate} ${version} is not an authenticated equivalent package payload on crates.io." >&2
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
