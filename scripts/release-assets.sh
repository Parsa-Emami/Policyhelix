#!/usr/bin/env bash
set -euo pipefail

mode=${1:?expected pack, verify or download}
assets=${2:?expected asset directory}
commit=${3:?expected full source commit}
[[ "$commit" =~ ^[0-9a-f]{40}$ ]]
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
manifest="$root/docs/release/RELEASE_MANIFEST.json"
repo=$(jq -er .repository "$manifest")
tag=$(jq -er .tag "$manifest")
version=$(jq -er .version "$manifest")
mapfile -t names < <(jq -er '.assets[]' "$manifest")
[[ ${#names[@]} == 5 && "${names[4]}" == SHA256SUMS.txt ]]
for name in "${names[@]}"; do [[ "$name" =~ ^[A-Za-z0-9._-]+$ && "$name" != .* ]]; done

check_identity() {
  jq -e --arg commit "$commit" --arg version "$version" '
    .project == "PolicyHelix" and .version == $version and
    .sourceCommit == $commit and .dirty == false and .profile == "local-demo" and
    .engineReady == true and .offlineRulesIncluded == true and
    .signature.algorithm == "github-artifact-attestation"
  ' "$1" >/dev/null
}

case "$mode" in
  pack)
    release=${4:?expected packaged release directory}
    [[ "$(git -C "$root" rev-parse HEAD)" == "$commit" ]]
    [[ -z "$(git -C "$root" status --porcelain)" ]]
    check_identity "$release/release.json"
    [[ ! -e "$release/SHA256SUMS.txt.sig" ]]
    (cd -- "$release" && sha256sum --strict -c SHA256SUMS.txt >/dev/null)
    mkdir -- "$assets"
    tar --sort=name --format=gnu --mtime="@$(git -C "$root" show -s --format=%ct "$commit")" \
      --owner=0 --group=0 --numeric-owner -C "$release" -cf - . | gzip -n > "$assets/${names[0]}"
    cp -- "$release/policyhelix-source.tar.gz" "$assets/${names[1]}"
    cp -- "$release/sbom.json" "$assets/${names[2]}"
    cp -- "$release/release.json" "$assets/${names[3]}"
    (cd -- "$assets" && sha256sum -- "${names[@]:0:4}" > SHA256SUMS.txt)
    ;;
  download)
    release_api="https://api.github.com/repos/$repo/releases/tags/$tag"
    curl -fsSL --retry 3 --max-time 45 "$release_api" | jq -e \
      --arg commit "$commit" --arg tag "$tag" --argjson names "$(jq -c .assets "$manifest")" '
        .draft == false and .prerelease == false and .target_commitish == $commit and
        .tag_name == $tag and ([.assets[].name] | sort) == ($names | sort)
      ' >/dev/null
    [[ "$(git ls-remote --exit-code "https://github.com/$repo.git" "refs/tags/$tag" | cut -f1)" == "$commit" ]]
    mkdir -- "$assets"
    for name in "${names[@]}"; do
      curl -fsSL --retry 3 --max-time 90 --max-filesize 104857600 \
        "https://github.com/$repo/releases/download/$tag/$name" -o "$assets/$name"
    done
    ;;
  verify)
    gh attestation verify "$assets/SHA256SUMS.txt" --repo "$repo" \
      --signer-workflow "$(jq -er .signer_workflow "$manifest")" \
      --source-ref "$(jq -er .source_ref "$manifest")" --source-digest "$commit" \
      --deny-self-hosted-runners
    diff -u <(printf '%s\n' "${names[@]:0:4}") <(cut -c67- "$assets/SHA256SUMS.txt")
    (cd -- "$assets" && sha256sum --strict -c SHA256SUMS.txt)
    check_identity "$assets/release.json"
    if [[ ${4:-} ]]; then
      mkdir -- "$4"
      tar --no-same-owner --no-same-permissions -xzf "$assets/${names[0]}" -C "$4"
      cmp -- "$assets/release.json" "$4/release.json"
      (cd -- "$4" && sha256sum --strict -c SHA256SUMS.txt >/dev/null)
      "$4/engine/policyhelix" --version | jq -e --arg version "$version" '.version == $version' >/dev/null
    fi
    ;;
  *)
    exit 2
    ;;
esac
