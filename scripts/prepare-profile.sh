#!/usr/bin/env bash
set -euo pipefail

REQUEST_FILE="$1"
DEVICE_TREE="$2"
OUTPUT_DIR="$3"
GITHUB_OUTPUT_FILE="$4"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
WORK_DIR="$(mktemp -d "$RUNNER_TEMP/rodin-profile.XXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT
mkdir -p "$OUTPUT_DIR" "$RUNNER_TEMP/rodin-payload-bin"
[[ -d "$DEVICE_TREE/prebuilt" ]] || { echo "ERROR: device tree has no prebuilt directory: $DEVICE_TREE" >&2; exit 1; }

python3 - "$REQUEST_FILE" "$WORK_DIR" <<'PY'
import json
import pathlib
import sys

request = json.loads(pathlib.Path(sys.argv[1]).read_text())
source = request["source"]
pathlib.Path(sys.argv[2], "source.json").write_text(json.dumps(source))
PY

source_type="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["source"]["type"])' "$REQUEST_FILE")"
if [[ "$source_type" == url ]]; then
  ota_url="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["source"]["url"])' "$REQUEST_FILE")"
  curl --fail --location --retry 5 --retry-all-errors --connect-timeout 30 --max-time 10800 \
    --max-filesize "${MAX_OTA_BYTES:-12000000000}" \
    --output "$WORK_DIR/ota-download" "$ota_url"
  input_path="$WORK_DIR/ota-download"
else
  gh release download "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["source"]["tag"])' "$REQUEST_FILE")" \
    --repo "$GH_REPO" --dir "$WORK_DIR/input"
  python3 - "$REQUEST_FILE" "$WORK_DIR/input" <<'PY'
import json
import pathlib
import shutil
import sys

request = json.loads(pathlib.Path(sys.argv[1]).read_text())
root = pathlib.Path(sys.argv[2])
allowed = {"payload.bin", "ota.zip", "vendor_boot.img", "dtbo.img", "vendor_dlkm.img", "odm_dlkm.img", "vendor.img", "odm.img", "boot.img", "init_boot.img"}
files = request["source"].get("files")
if not isinstance(files, list) or not files:
    raise SystemExit("release input manifest is missing")
for item in files:
    name = item.get("name")
    if name not in allowed or not isinstance(item.get("size"), int):
        raise SystemExit("release input manifest contains an unsupported file")
    parts = item.get("parts")
    if parts is None:
        path = root / name
        if not path.is_file() or path.stat().st_size != item["size"]:
            raise SystemExit(f"release asset is missing or has the wrong size: {name}")
        continue
    if not isinstance(parts, int) or parts < 1 or parts > 1000:
        raise SystemExit(f"invalid chunk count for {name}")
    target = root / (name + ".assembled")
    with target.open("wb") as out:
        for number in range(1, parts + 1):
            part = root / f"{name}.part-{number:06d}"
            if not part.is_file():
                raise SystemExit(f"release chunk is missing: {part.name}")
            with part.open("rb") as source:
                shutil.copyfileobj(source, out, length=1024 * 1024)
    if target.stat().st_size != item["size"]:
        raise SystemExit(f"assembled input has the wrong size: {name}")
    target.replace(root / name)
PY
  input_path="$WORK_DIR/input"
fi

if [[ "$source_type" == release ]]; then
  if [[ -f "$input_path/payload.bin" ]]; then
    cp -f "$input_path/payload.bin" "$WORK_DIR/payload.bin"
  elif [[ -f "$input_path/ota.zip" ]]; then
    if unzip -Z1 "$input_path/ota.zip" | grep -qx 'payload.bin'; then
      unzip -p "$input_path/ota.zip" payload.bin > "$WORK_DIR/payload.bin"
    else
      echo 'ERROR: uploaded OTA ZIP does not contain a root-level payload.bin' >&2
      exit 1
    fi
  else
    for image in vendor_boot.img vendor_dlkm.img odm_dlkm.img vendor.img odm.img boot.img init_boot.img; do
      [[ ! -f "$input_path/$image" ]] || cp -f "$input_path/$image" "$OUTPUT_DIR/$image"
    done
  fi
elif unzip -Z1 "$input_path" > "$WORK_DIR/zip-list" 2>/dev/null; then
  # Android OTA ZIPs are sometimes reported by `file` as "Java archive data
  # (JAR)". JAR and OTA packages share the ZIP container format, so inspect
  # the archive itself instead of depending on the human-readable MIME label.
  if ! grep -Fxq 'payload.bin' "$WORK_DIR/zip-list"; then
    echo 'ERROR: OTA ZIP does not contain a root-level payload.bin' >&2
    exit 1
  fi
  unzip -p "$input_path" payload.bin > "$WORK_DIR/payload.bin"
elif [[ "$(head -c 4 "$input_path")" == CrAU ]]; then
  cp -f "$input_path" "$WORK_DIR/payload.bin"
else
  echo "ERROR: unsupported input file type: $(file -b "$input_path")" >&2
  exit 1
fi

if [[ -s "$WORK_DIR/payload.bin" ]]; then
  export GOBIN="$RUNNER_TEMP/payload-tools"
  mkdir -p "$GOBIN"
  go install github.com/ssut/payload-dumper-go@latest
  # Extract only the partitions this profile needs. A full OTA payload is
  # several GiB and the runner filesystem is the binding constraint here.
  "$GOBIN/payload-dumper-go" -q -p 'boot,vendor_boot,vendor_dlkm,odm_dlkm,vendor,odm' -o "$WORK_DIR/extracted" "$WORK_DIR/payload.bin"
  for image in vendor_boot.img vendor_dlkm.img odm_dlkm.img vendor.img odm.img boot.img; do
    [[ ! -f "$WORK_DIR/extracted/$image" ]] || cp -f "$WORK_DIR/extracted/$image" "$OUTPUT_DIR/$image"
  done
  rm -f "$WORK_DIR/payload.bin"
fi

for required in boot.img vendor_boot.img vendor_dlkm.img odm_dlkm.img; do
  [[ -s "$OUTPUT_DIR/$required" ]] || {
    echo "ERROR: required profile input is missing: $required" >&2
    exit 1
  }
done

unpack_dir="$WORK_DIR/vendor_boot-unpacked"
python3 "$ORANGEFOX_TOP/system/tools/mkbootimg/unpack_bootimg.py" \
  --boot_img "$OUTPUT_DIR/vendor_boot.img" --out "$unpack_dir"
[[ -s "$unpack_dir/vendor_ramdisk00" && -s "$unpack_dir/dtb" ]] || {
  echo 'ERROR: vendor_boot is missing its type-1 platform ramdisk or DTB' >&2
  exit 1
}
ramdisk_sha="$(sha256sum "$unpack_dir/vendor_ramdisk00" | awk '{print $1}')"
dtb_sha="$(sha256sum "$unpack_dir/dtb" | awk '{print $1}')"
requested="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("profile", "auto"))' "$REQUEST_FILE")"
platform_cpio="$WORK_DIR/platform-profile.cpio"
extcon_module="$WORK_DIR/extcon-mtk-usb.ko"
lz4 -d -f "$unpack_dir/vendor_ramdisk00" "$platform_cpio" >/dev/null
cpio -i --quiet --to-stdout lib/modules/extcon-mtk-usb.ko \
  < "$platform_cpio" > "$extcon_module"
mapfile -t vermagic_values < <(strings -a "$extcon_module" | sed -n 's/^vermagic=\([^ ]*\).*/\1/p' | sort -u)
[[ "${#vermagic_values[@]}" -eq 1 ]] || {
  echo 'ERROR: could not identify one kernel vermagic from the input platform extcon module.' >&2
  exit 1
}
kernel_vermagic="${vermagic_values[0]}"
case "$kernel_vermagic" in
  6.6.77-*) compatible_variant=cn ;;
  6.6.89-*) compatible_variant=global ;;
  *)
    compatible_variant=unknown
    ;;
esac
case "$requested" in
  auto)
    [[ "$compatible_variant" != unknown ]] || {
      echo "ERROR: cannot infer CN/Global packaging profile from kernel ABI '$kernel_vermagic'; select CN or Global explicitly. Modules will still be taken from this firmware." >&2
      exit 1
    }
    detected="$compatible_variant"
    ;;
  cn|global)
    [[ "$compatible_variant" == unknown || "$requested" == "$compatible_variant" ]] || {
      echo "ERROR: selected Recovery module ABI '$requested' conflicts with input kernel ABI '$kernel_vermagic' ($compatible_variant)." >&2
      exit 1
    }
    detected="$requested"
    ;;
  *)
    echo "ERROR: unsupported Recovery module ABI selection '$requested'." >&2
    exit 1
    ;;
esac
firmware_variant="$detected"
cp -f "$unpack_dir/vendor_ramdisk00" "$OUTPUT_DIR/vendor_ramdisk00"
cp -f "$unpack_dir/dtb" "$OUTPUT_DIR/dtb"
python3 - "$OUTPUT_DIR/profile.json" "$REQUEST_FILE" "$firmware_variant" "$ramdisk_sha" "$dtb_sha" "$kernel_vermagic" <<'PY'
import hashlib
import json
import pathlib
import sys

request = json.loads(pathlib.Path(sys.argv[2]).read_text())
data = {
    "schema": 1,
    "firmware_variant": sys.argv[3],
    "baseline_source": "verified rodin device-tree platform runtime",
    "source_platform_ramdisk_sha256": sys.argv[4],
    "platform_ramdisk_sha256": sys.argv[4],
    "dtb_sha256": sys.argv[5],
    "kernel_vermagic": sys.argv[6],
    "inputs": {},
    "created_at": request.get("created_at"),
}
for path in sorted(pathlib.Path(sys.argv[1]).parent.iterdir()):
    if path.is_file() and (path.name.endswith(".img") or path.name in {"vendor_ramdisk00", "dtb"}):
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        data["inputs"][path.name] = {"size": path.stat().st_size, "sha256": digest.hexdigest()}
fingerprint = json.dumps(data["inputs"], sort_keys=True, separators=(",", ":")).encode()
data["profile_id"] = "rodin-" + data["firmware_variant"] + "-" + hashlib.sha256(fingerprint).hexdigest()[:16]
pathlib.Path(sys.argv[1]).write_text(json.dumps(data, indent=2) + "\n")
PY
python3 "$SCRIPT_DIR/create-profile-baseline.py" "$DEVICE_TREE" "$OUTPUT_DIR" "$firmware_variant"
echo "firmware_variant=$firmware_variant" >> "$GITHUB_OUTPUT_FILE"
echo "Created profile $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["profile_id"])') from this request's firmware inputs; kernel and Recovery modules were extracted from this firmware."
