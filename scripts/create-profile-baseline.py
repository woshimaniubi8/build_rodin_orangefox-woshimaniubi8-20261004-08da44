#!/usr/bin/env python3
import argparse
import gzip
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def replace_line_value(path, directive, marker, value, optional=False):
    lines = path.read_text().splitlines()
    indexes = [
        index for index, line in enumerate(lines)
        if line.lstrip().startswith(directive + " ") and marker in line
    ]
    if len(indexes) != 1:
        if optional and not indexes:
            return
        raise SystemExit(f"expected one profile guard containing {marker!r} in {path}; found {len(indexes)}")
    index = indexes[0]
    match = re.search(r"(?P<prefix>.*\s)(?P<value>[0-9a-fA-F]{64}|[0-9]+)(?P<suffix>\s*)$", lines[index])
    if not match:
        raise SystemExit(f"could not parse profile guard in {path}: {lines[index]}")
    lines[index] = match.group("prefix") + str(value) + match.group("suffix")
    path.write_text("\n".join(lines) + "\n")


def replace_guard_for_path(path, directive, marker, value):
    """Update one check_* line for an exact quoted path marker."""
    lines = path.read_text().splitlines()
    indexes = [
        index for index, line in enumerate(lines)
        if line.lstrip().startswith(directive + " ") and marker in line
    ]
    if len(indexes) != 1:
        raise SystemExit(f"expected one {directive} guard containing {marker!r} in {path}; found {len(indexes)}")
    index = indexes[0]
    match = re.search(r"(?P<prefix>.*\s)(?P<value>[0-9a-fA-F]{64}|[0-9]+)(?P<suffix>\s*)$", lines[index])
    if not match:
        raise SystemExit(f"could not parse profile guard in {path}: {lines[index]}")
    lines[index] = match.group("prefix") + str(value) + match.group("suffix")
    path.write_text("\n".join(lines) + "\n")


def replace_script_hash_guard(text, marker, value):
    lines = text.splitlines()
    targets = [
        index for index, line in enumerate(lines)
        if marker in line and (
            "check_sha256" in line or
            (index > 0 and "check_sha256" in lines[index - 1])
        )
    ]
    if len(targets) != 1:
        raise SystemExit(f"expected one script guard containing {marker!r}; found {len(targets)}")
    target = targets[0]
    guard = target if "check_sha256" in lines[target] else target - 1
    if guard < 0 or "check_sha256" not in lines[guard]:
        raise SystemExit(f"could not find the check_sha256 line for {marker!r}")
    match = re.search(r"(?P<prefix>check_sha256\s+)[0-9a-fA-F]{64}(?P<suffix>.*)$", lines[guard])
    if not match:
        raise SystemExit(f"could not parse check_sha256 guard for {marker!r}: {lines[guard]}")
    lines[guard] = match.group("prefix") + value + match.group("suffix")
    return "\n".join(lines) + "\n"


def module_vermagic(path):
    output = subprocess.run(["strings", "-a", str(path)], check=True, stdout=subprocess.PIPE).stdout.decode(errors="replace")
    values = [line.split("=", 1)[1].split()[0] for line in output.splitlines() if line.startswith("vermagic=")]
    if len(values) != 1:
        raise SystemExit(f"could not identify one module vermagic in {path}")
    return values[0]


def kernel_abi_key(release):
    """Return the stable Android GKI ABI portion of a rodin release string.

    Xiaomi's boot kernel and vendor modules can carry different local build
    suffixes (for example a GKI/commit suffix) while retaining the same
    Android kernel ABI and architecture.  Keep those suffixes in the profile,
    but use this narrow key for the compatibility check.  Unknown release
    formats are deliberately rejected instead of being guessed compatible.
    """
    parts = release.split("-")
    if len(parts) < 4:
        return None
    if not re.fullmatch(r"\d+\.\d+\.\d+", parts[0]):
        return None
    if not re.fullmatch(r"android\d+", parts[1]):
        return None
    if not parts[2].isdigit() or not re.fullmatch(r"\d+k", parts[-1]):
        return None
    return parts[0], parts[1], parts[2], parts[-1]


def kernel_releases_compatible(module_release, kernel_release_value):
    """Accept an exact release or a known same-ABI local suffix variant."""
    if module_release == kernel_release_value:
        return True
    module_key = kernel_abi_key(module_release)
    kernel_key = kernel_abi_key(kernel_release_value)
    return module_key is not None and module_key == kernel_key


RECOVERY_MODULES = (
    "scp.ko",
    "xiaomi_touch_rodin.ko",
    "goodix_core_rodin.ko",
    "focaltech_touch_rodin.ko",
    "nxp_i2c.ko",
    "p73.ko",
    "si_haptic.ko",
)


def recovery_module_tree_targets(variant, name):
    """Return device-tree blob paths for a selected Recovery module.

    CN's haptic module is an exception: ``device.mk`` copies its proprietary
    source blob into the Recovery ramdisk.  The ramdisk destination is not a
    tracked device-tree input and must therefore never be added to the blob
    manifest.
    """
    if name not in RECOVERY_MODULES:
        raise ValueError(f"not a Recovery module: {name}")
    if variant == "cn":
        if name == "si_haptic.ko":
            return ("proprietary/haptics/si_haptic.ko",)
        return (f"recovery/root/lib/modules/{name}",)
    if variant == "global":
        return (f"prebuilt/global/modules/{name}",)
    raise ValueError(f"unsupported firmware variant: {variant}")


# Some rodin vendor builds retain the source-tree module name
# ``xiaomi_touch_dali`` in dependent modules, while shipping the same exported
# interface under the device-specific ``xiaomi_touch_rodin.ko`` filename.
# Keep the dependency check enabled, but resolve this known rename to the
# supplied module instead of treating it as an absent dependency.
MODULE_DEPENDENCY_ALIASES = {
    "xiaomi_touch_dali": "xiaomi_touch_rodin",
}
RETURN_ZERO = bytes.fromhex("00008052c0035fd6")
PACIASP = bytes.fromhex("3f2303d5")
THP_DISABLED = bytes.fromhex("1fdd06b9")
THP_ENABLED = bytes.fromhex("09dd06b9")


def module_name_keys(name):
    """Return the raw and canonical keys for a module/dependency name."""
    raw = name.replace("-", "_")
    canonical = MODULE_DEPENDENCY_ALIASES.get(raw, raw)
    return tuple(dict.fromkeys((raw, canonical)))


def module_filename(mapping, name):
    """Look up a module filename while honoring known vendor renames."""
    for key in module_name_keys(name):
        if key in mapping:
            return mapping[key]
    return None


def module_present(names, name):
    return any(key in names for key in module_name_keys(name))


def elf_module(path):
    data = bytearray(path.read_bytes())
    header_format = "<16sHHIQQQIHHHHHH"
    section_format = "<IIQQQQIIQQ"
    symbol_format = "<IBBHQQ"
    if len(data) < struct.calcsize(header_format):
        raise SystemExit(f"Recovery module is too small to be ELF: {path.name}")
    header = struct.unpack_from(header_format, data)
    ident, elf_type, machine, _version, _entry, _phoff, shoff, _flags, _ehsize, _phentsize, _phnum, shentsize, shnum, shstrndx = header
    if ident[:4] != b"\x7fELF" or ident[4] != 2 or ident[5] != 1:
        raise SystemExit(f"Recovery module must be ELF64 little-endian: {path.name}")
    if elf_type != 1 or machine != 183:
        raise SystemExit(f"Recovery module must be AArch64 ET_REL: {path.name}")
    if shentsize < struct.calcsize(section_format) or shstrndx >= shnum or shoff + shnum * shentsize > len(data):
        raise SystemExit(f"Recovery module section table is invalid: {path.name}")
    sections = []
    for index in range(shnum):
        offset = shoff + index * shentsize
        if offset + struct.calcsize(section_format) > len(data):
            raise SystemExit(f"Recovery module section table is truncated: {path.name}")
        values = struct.unpack_from(section_format, data, offset)
        if values[1] != 8 and values[4] + values[5] > len(data):
            raise SystemExit(f"Recovery module section exceeds the file: {path.name}")
        sections.append({
            "index": index,
            "name_offset": values[0], "type": values[1], "flags": values[2],
            "offset": values[4], "size": values[5], "link": values[6],
            "info": values[7], "entsize": values[9],
        })
    names_section = sections[shstrndx]
    names = data[names_section["offset"]:names_section["offset"] + names_section["size"]]

    def string_at(table, offset):
        if offset < 0 or offset >= len(table):
            return ""
        end = table.find(b"\0", offset)
        if end < 0:
            return ""
        return table[offset:end].decode(errors="replace")

    for section in sections:
        section["name"] = string_at(names, section["name_offset"])
    symbols = {}
    for section in sections:
        if section["type"] != 2 or section["link"] >= len(sections):
            continue
        strings_section = sections[section["link"]]
        strings = data[strings_section["offset"]:strings_section["offset"] + strings_section["size"]]
        entry_size = section["entsize"] or struct.calcsize(symbol_format)
        if entry_size < struct.calcsize(symbol_format):
            raise SystemExit(f"Recovery module symbol table is invalid: {path.name}")
        for offset in range(section["offset"], section["offset"] + section["size"], entry_size):
            if offset + struct.calcsize(symbol_format) > len(data):
                raise SystemExit(f"Recovery module symbol table is truncated: {path.name}")
            name_offset, info, _other, section_index, value, size = struct.unpack_from(symbol_format, data, offset)
            name = string_at(strings, name_offset)
            if name and section_index < len(sections) and info & 0xF == 2:
                symbols.setdefault(name, []).append({"section": section_index, "value": value, "size": size})
    return data, sections, symbols


def module_dependencies(elf):
    data, sections, _symbols = elf
    modinfo = [section for section in sections if section["name"] == ".modinfo"]
    if len(modinfo) != 1:
        raise SystemExit("Recovery module does not have one ELF .modinfo section")
    section = modinfo[0]
    raw = bytes(data[section["offset"]:section["offset"] + section["size"]])
    entries = [item.decode(errors="strict") for item in raw.split(b"\0") if item]
    values = [item.split("=", 1)[1] for item in entries if item.startswith("depends=")]
    if len(values) > 1:
        raise SystemExit("Recovery module has multiple depends records")
    if not values or not values[0]:
        return []
    names = values[0].split(",")
    if any(not re.fullmatch(r"[A-Za-z0-9_.-]+", name) for name in names):
        raise SystemExit("Recovery module dependency metadata has an invalid name")
    return names


def module_name(elf):
    data, sections, _symbols = elf
    modinfo = [section for section in sections if section["name"] == ".modinfo"]
    if len(modinfo) != 1:
        raise SystemExit("Recovery module does not have one ELF .modinfo section")
    section = modinfo[0]
    raw = bytes(data[section["offset"]:section["offset"] + section["size"]])
    entries = [item.decode(errors="strict") for item in raw.split(b"\0") if item]
    values = [item.split("=", 1)[1] for item in entries if item.startswith("name=")]
    if len(values) != 1 or not re.fullmatch(r"[A-Za-z0-9_.-]+", values[0]):
        raise SystemExit("Recovery module does not have one valid .modinfo name")
    return values[0]


def function_file_offset(path, elf, name):
    data, sections, symbols = elf
    matches = [item for item in symbols.get(name, []) if item["section"] != 0]
    if len(matches) != 1:
        raise SystemExit(f"expected one defined ELF function {name!r} in {path.name}; found {len(matches)}")
    symbol = matches[0]
    section = sections[symbol["section"]]
    if section["type"] != 1 or not section["flags"] & 0x4 or symbol["size"] < 8:
        raise SystemExit(f"ELF function {name!r} has an invalid executable section/range in {path.name}")
    if symbol["value"] + symbol["size"] > section["size"]:
        raise SystemExit(f"ELF function {name!r} exceeds its section in {path.name}")
    return section["offset"] + symbol["value"], symbol["size"], symbol["section"]


def ensure_no_relocation(path, elf, target_section, start, size):
    data, sections, _symbols = elf
    for section in sections:
        if section["info"] != target_section or section["type"] not in {4, 9}:
            continue
        entry_size = section["entsize"] or (24 if section["type"] == 4 else 16)
        for offset in range(section["offset"], section["offset"] + section["size"], entry_size):
            if offset + 8 > len(data):
                raise SystemExit(f"relocation table is truncated in {path.name}")
            relocation_offset = struct.unpack_from("<Q", data, offset)[0]
            if start <= relocation_offset < start + size:
                raise SystemExit(f"refusing to patch relocated instructions in {path.name}")


def patch_function(path, elf, function_name):
    data, sections, _symbols = elf
    file_offset, size, section_index = function_file_offset(path, elf, function_name)
    section_value = file_offset - sections[section_index]["offset"]
    ensure_no_relocation(path, elf, section_index, section_value, len(RETURN_ZERO))
    current = bytes(data[file_offset:file_offset + 8])
    if current == RETURN_ZERO:
        return file_offset
    second_instruction = struct.unpack_from("<I", current, 4)[0]
    saves_frame = (
        second_instruction & 0xFFC003E0 == 0xA98003E0
        and second_instruction & 0x7C1F == 0x781D
    )
    allocates_stack = (
        second_instruction & 0xFFC003FF == 0xD10003FF
        and second_instruction & 0x003FFC00 != 0
    )
    if current[:4] != PACIASP or not (saves_frame or allocates_stack):
        raise SystemExit(f"unexpected prologue for {function_name} in {path.name}: {current.hex()}")
    data[file_offset:file_offset + len(RETURN_ZERO)] = RETURN_ZERO
    path.write_bytes(data)
    return file_offset


def patch_goodix_thp(path, elf):
    data, sections, _symbols = elf
    function_offset, function_size, section_index = function_file_offset(path, elf, "goodix_start_later_init")
    function = bytes(data[function_offset:function_offset + function_size])
    matches = []
    for needle in (THP_DISABLED, THP_ENABLED):
        position = 0
        while True:
            position = function.find(needle, position)
            if position < 0:
                break
            after = function[position + 12:position + 16]
            before = function[position - 20:position - 16] if position >= 20 else b""
            if before == bytes.fromhex("29008052") and after == bytes.fromhex("1f6d07b9"):
                matches.append((position, needle))
            position += 4
    if len(matches) != 1:
        raise SystemExit(f"could not uniquely identify the Goodix THP default instruction in {path.name}")
    relative, current = matches[0]
    file_offset = function_offset + relative
    section_value = file_offset - sections[section_index]["offset"]
    ensure_no_relocation(path, elf, section_index, section_value, len(THP_ENABLED))
    if current == THP_DISABLED:
        data[file_offset:file_offset + len(THP_ENABLED)] = THP_ENABLED
        path.write_bytes(data)
    return file_offset


def patch_touch_modules(staging):
    offsets = {name: {} for name in RECOVERY_MODULES}
    for name in RECOVERY_MODULES:
        path = staging / name
        if not path.is_file():
            raise SystemExit(f"required module was not extracted from this firmware: {name}")
        if name == "scp.ko":
            offsets[name]["init_module"] = patch_function(path, elf_module(path), "init_module")
        elif name in {"goodix_core_rodin.ko", "focaltech_touch_rodin.ko"}:
            for function in (
                "scp_tp_get_reserve_mem", "scp_tp_ipi_send", "scp_tp_sendparam",
                "scp_tp_init", "scp_tp_exit", "scp_tp_switch",
            ):
                offsets[name][function] = patch_function(path, elf_module(path), function)
            if name == "goodix_core_rodin.ko":
                offsets[name]["thp_default"] = patch_goodix_thp(path, elf_module(path))
    return offsets


def kernel_release(kernel_path):
    data = kernel_path.read_bytes()
    lz4_result = subprocess.run(["lz4", "-d", "-c", str(kernel_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if lz4_result.returncode == 0 and b"Linux version " in lz4_result.stdout:
        data = lz4_result.stdout
    elif data[:2] == b"\x1f\x8b":
        try:
            data = gzip.decompress(data)
        except OSError as error:
            raise SystemExit(f"could not decompress the boot kernel: {error}")
    match = re.search(rb"Linux version ([^\s]+)", data)
    if not match:
        raise SystemExit("could not read Linux release string from the kernel extracted from boot.img")
    return match.group(1).decode()


def extract_partition_modules(image, destination):
    with image.open("rb") as source:
        data = source.read(4096)
    raw_image = image
    if len(data) >= 4 and struct.unpack_from("<I", data)[0] == 0xED26FF3A:
        raw_image = destination.parent / (image.name + ".raw")
        subprocess.run(["simg2img", str(image), str(raw_image)], check=True)
        with raw_image.open("rb") as source:
            data = source.read(4096)
    destination.mkdir(parents=True, exist_ok=True)
    if len(data) >= 1028 and struct.unpack_from("<I", data, 1024)[0] == 0xE0F5E1E2:
        subprocess.run(["fsck.erofs", f"--extract={destination}", str(raw_image)], check=True)
    elif len(data) >= 1082 and data[1080:1082] == b"\x53\xef":
        for module_path in ("/lib/modules", "/usr/lib/modules"):
            result = subprocess.run(
                ["debugfs", "-R", f"rdump {module_path} {destination}", str(raw_image)],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )
            if result.returncode == 0 and any(destination.rglob("*.ko")):
                break
    else:
        description = subprocess.run(["file", "-b", str(image)], check=False, stdout=subprocess.PIPE, text=True).stdout.strip()
        raise SystemExit(f"unsupported module partition filesystem for {image.name}: {description}")
    if raw_image != image:
        raw_image.unlink(missing_ok=True)


def module_paths(root, name):
    candidates = [path for path in root.rglob(name) if path.is_file()]
    compressed = [path for suffix in (".xz", ".zst", ".gz", ".lz4") for path in root.rglob(name + suffix) if path.is_file()]
    if compressed:
        raise SystemExit(f"compressed kernel module is not supported: {compressed[0]}")
    for path in candidates:
        if not path.resolve().is_relative_to(root.resolve()):
            raise SystemExit(f"module path escapes the extracted partition: {path}")
    return candidates


def extract_ramdisk_modules(ramdisk):
    decompressed = subprocess.run(["lz4", "-d", "-c", str(ramdisk)], check=True, stdout=subprocess.PIPE).stdout
    listing = subprocess.run(["cpio", "-it", "--quiet"], input=decompressed, check=True, stdout=subprocess.PIPE).stdout.decode(errors="replace").splitlines()
    result = {}
    for name in RECOVERY_MODULES:
        matches = [item for item in listing if item.removeprefix("./").split("/")[-1] == name]
        if len(matches) > 1:
            raise SystemExit(f"vendor_boot platform ramdisk contains ambiguous copies of {name}")
        if matches:
            result[name] = subprocess.run(
                ["cpio", "-i", "--quiet", "--to-stdout", matches[0]],
                input=decompressed, check=True, stdout=subprocess.PIPE,
            ).stdout
    return result


def _extract_lz4_cpio(ramdisk, root, temporary):
    """Extract a legacy-LZ4 vendor ramdisk into a temporary directory."""
    root.mkdir(parents=True, exist_ok=True)
    archive = temporary / (root.name + ".cpio")
    subprocess.run(["lz4", "-d", "-f", str(ramdisk), str(archive)], check=True, stdout=subprocess.DEVNULL)
    with archive.open("rb") as archive_input:
        subprocess.run(
            ["cpio", "-idm", "--quiet", "--no-absolute-filenames"],
            cwd=root,
            stdin=archive_input,
            check=True,
        )
    return archive


def _pack_lz4_cpio(root, destination, temporary):
    """Pack a temporary ramdisk tree using the format accepted by mkbootimg."""
    archive = temporary / (destination.name + ".cpio")
    listing = subprocess.run(
        ["find", ".", "-print0"],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    with archive.open("wb") as output:
        subprocess.run(
            ["cpio", "--null", "-o", "--format=newc", "--quiet"],
            cwd=root,
            input=listing,
            stdout=output,
            check=True,
        )
    subprocess.run(
        ["lz4", "-l", "-12", "--favor-decSpeed", "-f", str(archive), str(destination)],
        check=True,
        stdout=subprocess.DEVNULL,
    )


def merge_platform_ramdisk(stock_ramdisk, supplied_ramdisk, destination, temporary):
    """Keep rodin's recovery runtime while validating a ROM platform fragment.

    Lineage's vendor_boot type-1 fragment contains only first-stage files and
    modules. It omits the Xiaomi recovery BootControl service and uses a
    nested fstab path. Starting with the verified rodin fragment preserves
    that service, its runtime libraries, and the device-specific root fstab;
    the supplied fragment contributes the platform module payload and metadata.
    Its duplicate first-stage libraries are intentionally not copied: they
    exceed rodin's 60 MB combined vendor-ramdisk budget after repacking.
    """
    stock_root = temporary / "stock-platform-root"
    supplied_root = temporary / "supplied-platform-root"
    _extract_lz4_cpio(stock_ramdisk, stock_root, temporary)
    _extract_lz4_cpio(supplied_ramdisk, supplied_root, temporary)

    nested_fstab = supplied_root / "first_stage_ramdisk/system/etc/fstab.mt6899"
    stock_root_fstab = stock_root / "first_stage_ramdisk/fstab.mt6899"
    # The verified rodin baseline has the first-stage fstab at the root-level
    # path used by this device. Do not promote a ROM's system-as-root fstab to
    # that path: Lineage's copy omits rodin-specific mi_ext and overlay entries.
    if not stock_root_fstab.is_file() and not nested_fstab.is_file():
        raise SystemExit("neither stock nor supplied platform ramdisk has a usable fstab.mt6899")

    supplied_modules = {
        item.name
        for item in (supplied_root / "lib/modules").glob("*.ko")
        if item.is_file()
    }
    required_modules = {
        "charger_class.ko",
        "extcon-mtk-usb.ko",
        "mt6375-charger.ko",
        "mtk_charger_framework.ko",
        "mtu3.ko",
        "tcpc_class.ko",
        "tcpc_mt6375.ko",
        "xhci-mtk-hcd-v2.ko",
    }
    missing_modules = sorted(required_modules - supplied_modules)
    if missing_modules:
        raise SystemExit(
            "supplied platform ramdisk is missing required rodin modules: "
            + ", ".join(missing_modules)
        )
    stock_modules = {
        item.name
        for item in (stock_root / "lib/modules").glob("*.ko")
        if item.is_file()
    }
    if stock_modules != supplied_modules:
        missing = ", ".join(sorted(stock_modules - supplied_modules)) or "none"
        extra = ", ".join(sorted(supplied_modules - stock_modules)) or "none"
        raise SystemExit(
            "supplied platform module set differs from the verified rodin baseline "
            f"(missing: {missing}; extra: {extra})"
        )

    # Replace only the platform module payload and its small dependency/load
    # metadata. Keep the stock first-stage userspace out of the overlay; the
    # supplied ROM's copies are system-as-root-only and are not a recovery
    # runtime.
    supplied_modules_root = supplied_root / "lib/modules"
    stock_modules_root = stock_root / "lib/modules"
    for source in sorted(supplied_modules_root.iterdir()):
        if source.is_file():
            shutil.copy2(source, stock_modules_root / source.name)
    if not (stock_root / "first_stage_ramdisk/fstab.mt6899").is_file():
        raise SystemExit("verified rodin platform baseline has no usable fstab.mt6899")
    if not (stock_root / "system/bin/hw/android.hardware.boot-service.mtk_recovery").is_file():
        raise SystemExit("stock rodin platform baseline lost its BootControl service")
    if not (stock_root / "system/etc/vintf/manifest/android.hardware.boot-service.mtk.xml").is_file():
        raise SystemExit("stock rodin platform baseline lost its BootControl manifest")
    _pack_lz4_cpio(stock_root, destination, temporary)
    print(
        "Using the verified rodin platform runtime "
        f"(overlaid {len(supplied_modules)} supplied platform modules; stock "
        "BootControl, fstab and first-stage userspace retained)."
    )


def platform_module_files(ramdisk):
    decompressed = subprocess.run(["lz4", "-d", "-c", str(ramdisk)], check=True, stdout=subprocess.PIPE).stdout
    listing = subprocess.run(["cpio", "-it", "--quiet"], input=decompressed, check=True, stdout=subprocess.PIPE).stdout.decode(errors="replace").splitlines()
    result = {}
    for item in listing:
        normalized_path = item.removeprefix("./")
        if not normalized_path.startswith("lib/modules/") or not normalized_path.endswith(".ko"):
            continue
        filename = normalized_path.split("/")[-1]
        name = filename[:-3].replace("-", "_")
        if name in result and result[name] != filename:
            raise SystemExit(f"vendor_boot platform ramdisk has ambiguous module name {name}")
        result[name] = filename
    return result


def source_modules_dep(root):
    """Read module filename dependencies from a supplied firmware tree.

    Vendor modules occasionally retain stale source-tree names in `.modinfo`.
    The firmware's `modules.dep` is the packaging-time dependency graph and
    therefore takes precedence when it provides an entry for a selected module.
    """
    entries = {}
    for path in sorted(root.rglob("modules.dep")):
        for number, line in enumerate(path.read_text(errors="strict").splitlines(), 1):
            if not line.strip():
                continue
            if ":" not in line:
                raise SystemExit(f"invalid modules.dep entry at {path}:{number}")
            module_path, dependency_paths = line.split(":", 1)
            module = Path(module_path.strip()).name
            if not module.endswith(".ko"):
                raise SystemExit(f"invalid module filename in {path}:{number}: {module_path!r}")
            dependencies = []
            for dependency_path in dependency_paths.split():
                dependency = Path(dependency_path).name
                if not dependency.endswith(".ko"):
                    raise SystemExit(f"invalid dependency filename in {path}:{number}: {dependency_path!r}")
                dependencies.append(dependency)
            previous = entries.get(module)
            if previous is not None and previous != dependencies:
                raise SystemExit(f"conflicting modules.dep entries for {module} in {root}")
            entries[module] = dependencies
    return entries


def update_modules_dep(device_tree, module_metadata, platform_modules):
    path = device_tree / "recovery/root/lib/modules/modules.dep"
    lines = path.read_text().splitlines()
    selected_modules = {Path(filename).stem.replace("-", "_"): filename for filename in module_metadata}
    for module, metadata in module_metadata.items():
        dependencies = metadata["depends"]
        missing = [
            name for name in dependencies
            if not module_present(platform_modules, name) and not module_filename(selected_modules, name)
        ]
        if missing:
            raise SystemExit(f"{module} depends on module(s) missing from this vendor_boot and Recovery module set: {', '.join(missing)}")
        dependency_files = {
            name: module_filename(selected_modules, name) or module_filename(platform_modules, name)
            for name in dependencies
        }
        entry = f"/lib/modules/{module}:" + "".join(
            f" /lib/modules/{dependency_files[name]}"
            for name in dependencies
        )
        indexes = [index for index, line in enumerate(lines) if line.split(":", 1)[0] == f"/lib/modules/{module}"]
        if len(indexes) > 1:
            raise SystemExit(f"expected one modules.dep entry for {module}; found {len(indexes)}")
        if indexes:
            lines[indexes[0]] = entry
        else:
            # Modules loaded directly by a Recovery service (for example the
            # independent haptics loader) are not necessarily listed in the
            # stock recovery modules.dep. Keep the generated graph complete
            # by adding an explicit empty entry rather than rejecting them.
            lines.append(entry)
    path.write_text("\n".join(lines) + "\n")
    return path


def clear_profile_module_state(device_tree):
    extra_dir = device_tree / "prebuilt/profile/modules"
    stale = {path.name for path in extra_dir.glob("*.ko")} if extra_dir.is_dir() else set()
    if extra_dir.exists():
        shutil.rmtree(extra_dir)
    if not stale:
        return
    modules_dep = device_tree / "recovery/root/lib/modules/modules.dep"
    if modules_dep.is_file():
        stale_paths = {f"/lib/modules/{name}:" for name in stale}
        lines = [line for line in modules_dep.read_text().splitlines() if not any(line.startswith(item) for item in stale_paths)]
        modules_dep.write_text("\n".join(lines) + "\n")
    loader = device_tree / "recovery/root/system/bin/load-touch-modules.sh"
    if loader.is_file():
        lines = [
            line for line in loader.read_text().splitlines()
            if not any(line.startswith(f"load_module {name} || exit 6") for name in stale)
        ]
        loader.write_text("\n".join(lines) + "\n")


def update_device_module_copy_rules(device_tree, dynamic_modules):
    device_mk = device_tree / "device.mk"
    text = device_mk.read_text()
    marker = "RODIN_RECOVERY_PROFILE_MODULE_COPY_FILES :="
    if marker not in text:
        insertion = (
            "RODIN_RECOVERY_PROFILE_MODULE_DIR := $(DEVICE_PATH)/prebuilt/profile/modules\n"
            "RODIN_RECOVERY_PROFILE_MODULE_COPY_FILES := $(foreach module,$(notdir $(wildcard $(RODIN_RECOVERY_PROFILE_MODULE_DIR)/*.ko)),$(RODIN_RECOVERY_PROFILE_MODULE_DIR)/$(module):recovery/root/lib/modules/$(module))\n\n"
        )
        if "PRODUCT_COPY_FILES += \\" not in text:
            raise SystemExit(f"could not locate PRODUCT_COPY_FILES block in {device_mk}")
        text = text.replace("PRODUCT_COPY_FILES += \\" , insertion + "PRODUCT_COPY_FILES += \\" , 1)
    copy_marker = "    $(RODIN_RECOVERY_EXTRA_MODULE_COPY_FILES) \\\n"
    if "$(RODIN_RECOVERY_PROFILE_MODULE_COPY_FILES)" not in text:
        if text.count(copy_marker) != 1:
            raise SystemExit(f"could not locate recovery module copy insertion point in {device_mk}")
        text = text.replace(copy_marker, copy_marker + "    $(RODIN_RECOVERY_PROFILE_MODULE_COPY_FILES) \\\n", 1)
    device_mk.write_text(text)
    if dynamic_modules:
        extra_dir = device_tree / "prebuilt/profile/modules"
        for name in dynamic_modules:
            if not (extra_dir / name).is_file():
                raise SystemExit(f"profile dependency module was not staged: {name}")


def update_touch_module_loader(device_tree, module_metadata, platform_modules):
    loader = device_tree / "recovery/root/system/bin/load-touch-modules.sh"
    text = loader.read_text()
    by_name = {metadata["module_name"].replace("-", "_"): filename for filename, metadata in module_metadata.items()}
    loaded = set()
    order = (
        "scp.ko", "xiaomi_touch_rodin.ko",
        "goodix_core_rodin.ko", "focaltech_touch_rodin.ko",
    )

    def dependencies_for(filename, seen):
        metadata = module_metadata[filename]
        result = []
        for dependency in metadata["depends"]:
            normalized = module_name_keys(dependency)[-1]
            if normalized in loaded or module_present(platform_modules, dependency):
                continue
            dependency_file = module_filename(by_name, dependency)
            if not dependency_file:
                raise SystemExit(f"touch loader dependency is not packaged: {dependency}")
            if normalized in seen:
                raise SystemExit(f"cyclic Recovery module dependency at {dependency}")
            nested = dependencies_for(dependency_file, seen | {normalized})
            result.extend(nested)
            if dependency_file not in {item[0] for item in result} and normalized not in loaded:
                result.append((dependency_file, normalized))
        return result

    lines = text.splitlines()
    for filename in order:
        metadata = module_metadata[filename]
        module_id = module_name_keys(metadata["module_name"])[-1]
        marker = f"load_module {filename} || exit "
        indexes = [index for index, line in enumerate(lines) if line.startswith(marker)]
        if len(indexes) != 1:
            raise SystemExit(f"expected one touch-loader command for {filename}; found {len(indexes)}")
        additions = []
        for dependency_file, dependency_id in dependencies_for(filename, {module_id}):
            if dependency_id not in loaded:
                additions.append(f"load_module {dependency_file} || exit 6")
                loaded.add(dependency_id)
        index = indexes[0]
        lines[index:index] = additions
        loaded.add(module_id)
    loader.write_text("\n".join(lines) + "\n")


def update_callback_module_allowlist(device_tree):
    callback = device_tree / "fox_callback.sh"
    text = callback.read_text()
    variant_marker = 'firmware_variant="${RODIN_FIRMWARE_VARIANT:-cn}"'
    if 'device_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"' not in text:
        if text.count(variant_marker) != 1:
            raise SystemExit(f"could not locate firmware variant initialization in {callback}")
        text = text.replace(
            variant_marker,
            'device_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"\n' + variant_marker,
            1,
        )
    old = '                *)\n                    rm -f "$module"\n                    ;;'
    new = (
        '                *)\n'
        '                    if [ -f "$device_dir/prebuilt/profile/modules/$(basename "$module")" ]; then\n'
        '                        :\n'
        '                    else\n'
        '                        rm -f "$module"\n'
        '                    fi\n'
        '                    ;;'
    )
    if new not in text:
        if text.count(old) != 1:
            raise SystemExit(f"could not locate module pruning case in {callback}")
        text = text.replace(old, new, 1)
    callback.write_text(text)


def update_repacker_module_guard(device_tree):
    build = device_tree / "tools/build-system-compatible-vendor-boot.sh"
    text = build.read_text()
    marker = '    cp -a "${DEVICE_DIR}/prebuilt/global/modules/." "$expected_dir/"\n'
    if marker not in text:
        raise SystemExit(f"could not locate Global module fixture copy in {build}")
    if 'prebuilt/profile/modules/.' not in text:
        text = text.replace(marker, marker + '    cp -a "${DEVICE_DIR}/prebuilt/profile/modules/." "$expected_dir/" 2>/dev/null || true\n', 1)
    start = text.find("    for module in \\\n", text.find("verify_global_recovery_modules()"))
    if start < 0:
        raise SystemExit(f"could not locate Global recovery module verification loop in {build}")
    end = text.find("    done", start)
    if end < 0:
        raise SystemExit(f"Global recovery module verification loop is malformed in {build}")
    end += len("    done")
    replacement = '''    for expected_module in "$expected_dir"/*.ko; do
        [ -f "$expected_module" ] || continue
        module="${expected_module##*/}"
        archive_path="lib/modules/${module}"
        extracted_module="${work_dir}/global-${module}"
        if ! cpio -it --quiet < "$recovery_cpio" | grep -E "^(\\./)?${archive_path}$" >/dev/null; then
            echo "Global recovery ramdisk is missing required module: ${module}" >&2
            exit 1
        fi
        cpio -i --quiet --to-stdout "$archive_path" < "$recovery_cpio" > "$extracted_module"
        if ! cmp -s "$expected_module" "$extracted_module"; then
            echo "Global recovery module does not match the selected firmware input: ${module}" >&2
            exit 1
        fi
    done'''
    text = text[:start] + replacement + text[end:]
    build.write_text(text)


def prepare_recovery_modules(device_tree, input_dir, variant, kernel_file, kernel_release_value, temporary):
    clear_profile_module_state(device_tree)
    selected = {}
    sources = []
    source_roots = []
    source_dependency_maps = {}
    dependency_details = {}

    def collect(source_name, modules):
        for name, path in modules.items():
            if name in selected:
                previous_path, previous_source = selected[name]
                if sha256(previous_path) != sha256(path):
                    raise SystemExit(f"conflicting firmware copies of {name} in {previous_source} and {source_name}")
            else:
                selected[name] = (path, source_name)

    def effective_dependencies(filename):
        """Return the firmware-authoritative dependencies for one module."""
        if filename in dependency_details:
            return dependency_details[filename]
        source_path, source_name = selected[filename]
        roots = [root for name, root in source_roots if name == source_name]
        if len(roots) != 1:
            raise SystemExit(f"could not identify the firmware source root for {filename}")
        if source_name not in source_dependency_maps:
            source_dependency_maps[source_name] = source_modules_dep(roots[0])
        modinfo_dependencies = module_dependencies(elf_module(source_path))
        packaged_dependencies = source_dependency_maps[source_name].get(source_path.name)
        if packaged_dependencies is None:
            aliases = {
                raw: module_name_keys(raw)[-1]
                for raw in modinfo_dependencies
                if module_name_keys(raw)[-1] != raw
            }
            if aliases:
                print(
                    f"WARNING: {filename} has stale firmware dependency names "
                    f"({', '.join(f'{raw}->{resolved}' for raw, resolved in aliases.items())}); "
                    "using the verified Rodin module aliases."
                )
            details = {
                "depends": modinfo_dependencies,
                "modinfo_depends": modinfo_dependencies,
                "dependency_source": "modinfo",
            }
        else:
            dependencies = [Path(item).stem for item in packaged_dependencies]
            if [item.replace("-", "_") for item in modinfo_dependencies] != [item.replace("-", "_") for item in dependencies]:
                print(
                    f"WARNING: {filename} .modinfo dependencies ({', '.join(modinfo_dependencies) or 'none'}) "
                    f"differ from {source_name}/modules.dep ({', '.join(dependencies) or 'none'}); "
                    "using the firmware modules.dep entry."
                )
            details = {
                "depends": dependencies,
                "modinfo_depends": modinfo_dependencies,
                "dependency_source": f"{source_name}/modules.dep",
            }
        dependency_details[filename] = details
        return details

    for partition in ("vendor_dlkm", "odm_dlkm"):
        image = input_dir / f"{partition}.img"
        if not image.is_file():
            continue
        root = temporary / f"extract-{partition}"
        extract_partition_modules(image, root)
        source_roots.append((partition, root))
        found = {}
        for name in RECOVERY_MODULES:
            paths = module_paths(root, name)
            if len(paths) > 1:
                raise SystemExit(f"{image.name} contains multiple copies of {name}")
            if paths:
                found[name] = paths[0]
        collect(partition, found)
        sources.append(partition)

    ramdisk_modules = extract_ramdisk_modules(input_dir / "vendor_ramdisk00")
    ramdisk_root = temporary / "vendor-ramdisk-modules"
    ramdisk_root.mkdir(parents=True, exist_ok=True)
    ramdisk_paths = {}
    for name, content in ramdisk_modules.items():
        path = ramdisk_root / name
        path.write_bytes(content)
        ramdisk_paths[name] = path
    collect("vendor_boot:vendor_ramdisk00", ramdisk_paths)
    sources.append("vendor_boot:vendor_ramdisk00")
    source_roots.append(("vendor_boot:vendor_ramdisk00", ramdisk_root))

    missing = [name for name in RECOVERY_MODULES if name not in selected]
    for partition in ("vendor", "odm") if missing else ():
        if not missing:
            break
        image = input_dir / f"{partition}.img"
        if not image.is_file():
            continue
        root = temporary / f"extract-{partition}"
        extract_partition_modules(image, root)
        source_roots.append((partition, root))
        found = {}
        for name in missing:
            paths = module_paths(root, name)
            if len(paths) > 1:
                raise SystemExit(f"{image.name} contains multiple copies of {name}")
            if paths:
                found[name] = paths[0]
        collect(partition, found)
        sources.append(partition)
        missing = [name for name in RECOVERY_MODULES if name not in selected]

    if missing:
        raise SystemExit("required Recovery modules are absent from this firmware: " + ", ".join(missing))

    platform_modules = platform_module_files(input_dir / "vendor_ramdisk00")
    for name, (path, source_name) in selected.items():
        if not path.is_file() or path.stat().st_size == 0:
            raise SystemExit(f"required Recovery module is empty: {name}")

    # Follow the firmware packaging dependency graph (falling back to ELF
    # .modinfo when the source partition has no modules.dep entry) and bring
    # dependencies absent from the stock platform fragment into Recovery.
    queue = list(RECOVERY_MODULES)
    visited = set()
    while queue:
        filename = queue.pop(0)
        if filename in visited:
            continue
        visited.add(filename)
        path, _source_name = selected[filename]
        for dependency in effective_dependencies(filename)["depends"]:
            selected_modules = {Path(item).stem.replace("-", "_"): item for item in selected}
            if module_present(platform_modules, dependency) or module_filename(selected_modules, dependency):
                continue
            matches = []
            possible_names = set()
            for candidate in module_name_keys(dependency):
                possible_names.update({
                    candidate + ".ko",
                    candidate.replace("_", "-") + ".ko",
                })
            for source_name, root in source_roots:
                found = [path for path in root.rglob("*.ko") if path.name in possible_names and path.is_file()]
                matches.extend((source_name, item) for item in found)
            if not matches:
                for partition in ("vendor", "odm"):
                    image = input_dir / f"{partition}.img"
                    if not image.is_file() or any(name == partition for name, _root in source_roots):
                        continue
                    root = temporary / f"extract-{partition}"
                    extract_partition_modules(image, root)
                    source_roots.append((partition, root))
                    sources.append(partition)
                    paths = [path for path in root.rglob("*.ko") if path.name in possible_names and path.is_file()]
                    matches.extend((partition, item) for item in paths)
            if not matches:
                raise SystemExit(f"{filename} requires {dependency}, absent from platform ramdisk and supplied partition modules")
            counts_by_source = {}
            for origin, _path in matches:
                counts_by_source[origin] = counts_by_source.get(origin, 0) + 1
            duplicated = [origin for origin, count in counts_by_source.items() if count > 1]
            if duplicated:
                raise SystemExit(f"firmware has multiple copies of dependency {dependency} in {', '.join(duplicated)}")
            hashes = {sha256(item) for _source, item in matches}
            if len(hashes) != 1:
                origins = ", ".join(sorted({source for source, _item in matches}))
                raise SystemExit(f"firmware has conflicting copies of dependency {dependency}: {origins}")
            source_order = {source: index for index, (source, _root) in enumerate(source_roots)}
            matches.sort(key=lambda item: (source_order[item[0]], str(item[1])))
            selected_filename = matches[0][1].name
            if Path(selected_filename).stem.replace("-", "_") not in module_name_keys(dependency):
                raise SystemExit(f"dependency module filename does not match declared module name: {selected_filename} for {dependency}")
            selected[selected_filename] = (matches[0][1], matches[0][0])
            queue.append(selected_filename)

    staging = temporary / "recovery-modules-patched"
    staging.mkdir()
    input_hashes = {}
    module_metadata = {}
    for name in selected:
        source_path, source_name = selected[name]
        if not source_path.resolve().is_relative_to(temporary.resolve()):
            raise SystemExit(f"module source is outside the isolated extraction directory: {source_path}")
        original = staging / name
        shutil.copyfile(source_path, original)
        input_hashes[name] = sha256(original)
        release = module_vermagic(original)
        if release != kernel_release_value:
            print(
                "WARNING: Recovery module vermagic differs from boot.img kernel: "
                f"{name} is {release}, boot.img kernel is {kernel_release_value}; continuing with the supplied module."
            )
        elf = elf_module(original)
        if module_name(elf).replace("-", "_") != Path(name).stem.replace("-", "_"):
            raise SystemExit(f"Recovery module filename does not match ELF .modinfo name: {name}")
        dependency_info = effective_dependencies(name)
        module_metadata[name] = {
            "module_name": module_name(elf), "source": source_name,
            "input_sha256": input_hashes[name], "vermagic": release,
            "depends": dependency_info["depends"],
            "modinfo_depends": dependency_info["modinfo_depends"],
            "dependency_source": dependency_info["dependency_source"],
            "dependency_aliases": {
                raw: module_name_keys(raw)[-1]
                for raw in dependency_info["modinfo_depends"]
                if module_name_keys(raw)[-1] != raw
            },
        }

    offsets = patch_touch_modules(staging)
    patched_hashes = {name: sha256(staging / name) for name in selected}
    for name in selected:
        module_metadata[name]["patched_sha256"] = patched_hashes[name]
        if name not in RECOVERY_MODULES:
            targets = (f"prebuilt/profile/modules/{name}",)
        else:
            targets = recovery_module_tree_targets(variant, name)
        for relative in targets:
            destination = device_tree / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(staging / name, destination)
    modules_dep = update_modules_dep(
        device_tree,
        module_metadata,
        platform_modules,
    )
    dynamic_modules = sorted(name for name in selected if name not in RECOVERY_MODULES)
    update_device_module_copy_rules(device_tree, dynamic_modules)
    update_callback_module_allowlist(device_tree)
    update_touch_module_loader(device_tree, module_metadata, set(platform_modules))
    update_repacker_module_guard(device_tree)
    update_module_patcher(device_tree, variant, offsets, input_hashes, patched_hashes)
    recovery_module_updates = {
        relative: device_tree / relative
        for name in RECOVERY_MODULES
        for relative in recovery_module_tree_targets(variant, name)
    }
    return {
        "updated": recovery_module_updates | {
            "recovery/root/lib/modules/modules.dep": modules_dep,
        } | {f"prebuilt/profile/modules/{name}": device_tree / "prebuilt/profile/modules" / name for name in dynamic_modules},
        "input_hashes": input_hashes,
        "patched_hashes": patched_hashes,
        "module_metadata": module_metadata,
        "patch_offsets": offsets,
        "kernel_sha256": sha256(kernel_file),
        "kernel_release": kernel_release_value,
        "source_partitions": sources,
    }


def update_module_patcher(device_tree, variant, offsets, input_hashes, patched_hashes):
    patcher = device_tree / "tools/patch-recovery-touch-modules.sh"
    text = patcher.read_text()
    prefix = "GLOBAL_" if variant == "global" else ""
    fields = {
        "scp.ko": ("SCP_STOCK_SHA256", "SCP_PATCHED_SHA256"),
        "goodix_core_rodin.ko": ("GOODIX_STOCK_SHA256", "GOODIX_PATCHED_SHA256"),
        "focaltech_touch_rodin.ko": ("FOCALTECH_STOCK_SHA256", "FOCALTECH_PATCHED_SHA256"),
    }
    for module, names in fields.items():
        for field, digest in zip(names, (input_hashes[module], patched_hashes[module])):
            name = prefix + field
            text, count = re.subn(rf"(?m)^{re.escape(name)}=\"[0-9a-fA-F]{{64}}\"$", f'{name}="{digest}"', text)
            if count != 1:
                raise SystemExit(f"expected one {name} in {patcher}; found {count}")

    def replace_offset(marker, offset, occurrence=0):
        nonlocal text
        lines = text.splitlines()
        matches = [i for i, line in enumerate(lines) if marker in line]
        if occurrence >= len(matches):
            raise SystemExit(f"expected patch offset {occurrence + 1} for {marker!r} in {patcher}; found {len(matches)}")
        line_index = matches[occurrence]
        lines[line_index], count = re.subn(r"\$\(\(0x[0-9a-fA-F]+\)\)", f"$(({offset:#x}))", lines[line_index], count=1)
        if count != 1:
            raise SystemExit(f"could not update patch offset for {marker!r} in {patcher}")
        text = "\n".join(lines) + "\n"

    replace_offset('"scp:init_module"', offsets["scp.ko"]["init_module"], 0 if variant == "global" else 1)
    for module, label_prefix in (("goodix_core_rodin.ko", "goodix"), ("focaltech_touch_rodin.ko", "focaltech")):
        for function in ("scp_tp_get_reserve_mem", "scp_tp_ipi_send", "scp_tp_sendparam", "scp_tp_init", "scp_tp_exit", "scp_tp_switch"):
            replace_offset(f'"{label_prefix}:{function}"', offsets[module][function])
    lines = text.splitlines()
    thp_lines = [i for i, line in enumerate(lines) if "local offset=$((0x" in line]
    if len(thp_lines) != 1:
        raise SystemExit(f"expected one Goodix THP patch offset in {patcher}")
    lines[thp_lines[0]], count = re.subn(r"0x[0-9a-fA-F]+", f"{offsets['goodix_core_rodin.ko']['thp_default']:#x}", lines[thp_lines[0]], count=1)
    if count != 1:
        raise SystemExit(f"could not update Goodix THP patch offset in {patcher}")
    patcher.write_text("\n".join(lines) + "\n")


def extract_ramdisk_profile(ramdisk, temporary):
    cpio_path = temporary / "platform.cpio"
    subprocess.run(["lz4", "-d", "-f", str(ramdisk), str(cpio_path)], check=True, stdout=subprocess.DEVNULL)
    archive = cpio_path.read_bytes()
    listing = subprocess.run(["cpio", "-it", "--quiet"], input=archive, check=True, stdout=subprocess.PIPE).stdout.decode().splitlines()
    required = {
        "system/bin/hw/android.hardware.boot-service.mtk_recovery",
        "first_stage_ramdisk/fstab.mt6899",
        "lib/modules/modules.load",
        "lib/modules/charger_class.ko",
        "lib/modules/extcon-mtk-usb.ko",
        "lib/modules/mt6375-charger.ko",
        "lib/modules/mtk_charger_framework.ko",
        "lib/modules/mtu3.ko",
        "lib/modules/tcpc_class.ko",
        "lib/modules/tcpc_mt6375.ko",
        "lib/modules/xhci-mtk-hcd-v2.ko",
    }
    normalized = {item.removeprefix("./") for item in listing}
    missing = sorted(required - normalized)
    if missing:
        raise SystemExit("platform ramdisk is missing required rodin files: " + ", ".join(missing))
    service_path = "system/bin/hw/android.hardware.boot-service.mtk_recovery"
    service = subprocess.run(
        ["cpio", "-i", "--quiet", "--to-stdout", service_path],
        input=archive,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    if not service.startswith(b"\x7fELF"):
        raise SystemExit("platform BootControl service is not a valid ELF")
    module_count = sum(
        1 for item in normalized
        if item.startswith("lib/modules/") and "/" not in item[len("lib/modules/"):]
        and item.endswith(".ko")
    )
    extcon = subprocess.run(
        ["cpio", "-i", "--quiet", "--to-stdout", "lib/modules/extcon-mtk-usb.ko"],
        input=archive,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    strings = subprocess.run(["strings", "-a"], input=extcon, check=True, stdout=subprocess.PIPE).stdout
    if b"vbus_switch\n" not in strings:
        raise SystemExit("platform extcon-mtk-usb module lacks the vbus_switch control")
    vermagic_values = [
        line.split(b"=", 1)[1].split()[0].decode()
        for line in strings.splitlines()
        if line.startswith(b"vermagic=")
    ]
    if len(vermagic_values) != 1:
        raise SystemExit("could not identify one kernel vermagic in platform extcon-mtk-usb.ko")
    return hashlib.sha256(service).hexdigest(), module_count, vermagic_values[0]


def update_manifest(device_tree, updated):
    manifest = device_tree / "manifests/device-blobs.sha256"
    lines = manifest.read_text().splitlines()
    for relative, path in updated.items():
        entry = "device/xiaomi/rodin/" + relative
        indexes = [index for index, line in enumerate(lines) if line.split(maxsplit=1)[-1:] == [entry]]
        if len(indexes) > 1 or (not indexes and not relative.startswith("prebuilt/profile/modules/")):
            raise SystemExit(f"device blob manifest must contain exactly one entry for {entry}")
        replacement = f"{sha256(path)}  {entry}"
        if indexes:
            lines[indexes[0]] = replacement
        else:
            lines.append(replacement)
    manifest.write_text("\n".join(lines) + "\n")
    return sha256(manifest)


def update_tree_guards(device_tree, variant, updated, boot_control_sha, module_count):
    verify = device_tree / "tools/verify-build-inputs.sh"
    for relative, path in updated.items():
        marker = f'"${{DEVICE_DIR}}/{relative}"'
        is_module = relative.endswith(".ko")
        # This generated file is integrity-checked through the blob manifest;
        # the pinned verify script intentionally validates its dependency
        # contents instead of maintaining a separate per-file hash line.
        dynamic_modules_dep = relative == "recovery/root/lib/modules/modules.dep"
        replace_line_value(
            verify,
            "check_sha256",
            marker,
            sha256(path),
            optional=is_module or relative == "prebuilt/kernel" or dynamic_modules_dep,
        )
        replace_line_value(verify, "check_size", marker, path.stat().st_size, optional=True)
    # The manifest is intentionally rewritten for every request profile. A
    # fixed hash of the manifest itself would reject those valid updates.
    verify_text = verify.read_text()
    verify_text, manifest_guard_count = re.subn(
        r'(?m)^check_sha256 "\$\{DEVICE_DIR\}/manifests/device-blobs\.sha256" [0-9a-fA-F]{64}\n',
        "",
        verify_text,
    )
    if manifest_guard_count != 1:
        raise SystemExit(f"expected one pinned manifest self-hash in {verify}; found {manifest_guard_count}")
    verify.write_text(verify_text)
    if variant == "global":
        # The verifier has explicit Global baseline guards in addition to the
        # manifest entry. They must follow the request-local platform blob or
        # the later CI preflight will reject the correctly generated profile.
        marker = '"${DEVICE_DIR}/prebuilt/global/vendor_ramdisk00"'
        replace_guard_for_path(verify, "check_size", marker, updated["prebuilt/global/vendor_ramdisk00"].stat().st_size)
        replace_guard_for_path(verify, "check_sha256", marker, sha256(updated["prebuilt/global/vendor_ramdisk00"]))

    build = device_tree / "tools/build-system-compatible-vendor-boot.sh"
    text = build.read_text()
    branch_start = text.find(f"    {variant})")
    if branch_start < 0:
        raise SystemExit(f"device-tree build script has no {variant} firmware branch")
    branch_end = text.find("        ;;", branch_start)
    if branch_end < 0:
        raise SystemExit(f"device-tree {variant} firmware branch is malformed")
    branch = text[branch_start:branch_end]
    branch, replacements = re.subn(
        r'(STOCK_RAMDISK_SHA256=")[0-9a-f]{64}(" )?',
        lambda match: match.group(1) + sha256(updated[f"prebuilt/{'global/' if variant == 'global' else ''}vendor_ramdisk00"]) + (match.group(2) or ""),
        branch,
    )
    if replacements != 1:
        raise SystemExit(f"expected one {variant} platform ramdisk hash in {build}")
    text = text[:branch_start] + branch + text[branch_end:]
    text = replace_script_hash_guard(text, '"$STOCK_DTB"', sha256(updated["prebuilt/dtb/mt6899-rodin.dtb"]))
    text = replace_script_hash_guard(text, '"$stock_boot_control_service"', boot_control_sha)
    text, replacements = re.subn(
        r'(platform_module_count" -ne )\d+',
        lambda match: match.group(1) + str(module_count),
        text,
    )
    if replacements != 1:
        raise SystemExit(f"expected one platform module-count guard in {build}")
    build.write_text(text)


def main():
    parser = argparse.ArgumentParser(description="Create a build-local rodin firmware profile from the current request inputs.")
    parser.add_argument("device_tree", type=Path)
    parser.add_argument("input_dir", type=Path)
    parser.add_argument("variant", choices=("cn", "global"))
    args = parser.parse_args()

    input_dir = args.input_dir
    device_tree = args.device_tree
    inputs = {
        "prebuilt/vendor_boot_stock.img": input_dir / "vendor_boot.img",
        "prebuilt/dtb/mt6899-rodin.dtb": input_dir / "dtb",
        f"prebuilt/{'global/' if args.variant == 'global' else ''}vendor_ramdisk00": input_dir / "vendor_ramdisk00",
    }
    stock_relative = f"prebuilt/{'global/' if args.variant == 'global' else ''}vendor_ramdisk00"
    stock_source = device_tree / stock_relative
    if not stock_source.is_file() or stock_source.stat().st_size == 0:
        raise SystemExit(f"verified rodin platform baseline is missing: {stock_source}")
    # Keep the immutable baseline available while the per-request input is
    # copied over the same path below. Custom ROM vendor_boot fragments can be
    # first-stage-only; the baseline supplies the rodin recovery runtime.
    stock_snapshot_tmp = tempfile.TemporaryDirectory(prefix="rodin-stock-baseline-")
    stock_snapshot = Path(stock_snapshot_tmp.name) / "vendor_ramdisk00"
    shutil.copyfile(stock_source, stock_snapshot)
    for relative, source in inputs.items():
        if not source.is_file() or source.stat().st_size == 0:
            raise SystemExit(f"per-request profile input is missing: {source}")
        destination = device_tree / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)

    if inputs["prebuilt/vendor_boot_stock.img"].stat().st_size != 64 * 1024 * 1024:
        raise SystemExit("vendor_boot image must match rodin's 64 MiB partition size")
    boot_image = input_dir / "boot.img"
    if not boot_image.is_file() or boot_image.stat().st_size == 0:
        raise SystemExit("boot.img is required to extract and validate this firmware's kernel")
    unpacker_top = os.environ.get("ORANGEFOX_TOP")
    if not unpacker_top:
        raise SystemExit("ORANGEFOX_TOP is required to extract the boot kernel")
    unpacker = Path(unpacker_top) / "system/tools/mkbootimg/unpack_bootimg.py"
    if not unpacker.is_file():
        raise SystemExit(f"OrangeFox boot image unpacker is missing: {unpacker}")
    with tempfile.TemporaryDirectory(prefix="rodin-profile-check-") as temporary:
        temporary_path = Path(temporary)
        boot_unpack = temporary_path / "boot-unpacked"
        subprocess.run([
            sys.executable, str(unpacker), "--boot_img", str(boot_image), "--out", str(boot_unpack),
        ], check=True)
        extracted_kernel = boot_unpack / "kernel"
        if not extracted_kernel.is_file() or extracted_kernel.stat().st_size == 0:
            raise SystemExit("boot.img did not contain a kernel payload")
        kernel_path = device_tree / "prebuilt/kernel"
        kernel_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(extracted_kernel, kernel_path)
        kernel_release_value = kernel_release(kernel_path)

        merged_ramdisk = temporary_path / "merged-vendor_ramdisk00"
        merge_platform_ramdisk(
            stock_snapshot,
            inputs[stock_relative],
            merged_ramdisk,
            temporary_path,
        )
        shutil.copyfile(merged_ramdisk, inputs[stock_relative])
        boot_control_sha, module_count, kernel_vermagic = extract_ramdisk_profile(
            inputs[stock_relative],
            temporary_path,
        )
        if kernel_vermagic != kernel_release_value:
            if kernel_releases_compatible(kernel_vermagic, kernel_release_value):
                detail = "their normalized Android ABI and architecture match"
            else:
                detail = "their ABI/build identifiers differ"
            print(
                "WARNING: vendor_boot platform modules use "
                f"{kernel_vermagic}, but boot.img kernel reports {kernel_release_value}; "
                f"{detail}, continuing with the verified rodin platform runtime and supplied recovery modules."
            )
        dtb_check = temporary_path / "dtb-otg-check.img"
        subprocess.run([
            sys.executable,
            str(device_tree / "tools/patch-vendor-boot-dtb.py"),
            "--input", str(inputs["prebuilt/dtb/mt6899-rodin.dtb"]),
            "--output", str(dtb_check),
        ], check=True)
        firmware_modules = prepare_recovery_modules(
            device_tree, input_dir, args.variant, kernel_path, kernel_release_value, temporary_path,
        )

    updated = inputs | {"prebuilt/kernel": kernel_path} | firmware_modules["updated"]
    manifest_sha = update_manifest(device_tree, updated)
    update_tree_guards(device_tree, args.variant, updated, boot_control_sha, module_count)
    profile_path = input_dir / "profile.json"
    if profile_path.is_file():
        profile = json.loads(profile_path.read_text())
        profile["kernel"] = {
            "source": "boot.img",
            "release": firmware_modules["kernel_release"],
            "sha256": firmware_modules["kernel_sha256"],
        }
        profile["platform_runtime"] = {
            "source": "verified device-tree stock baseline",
            "input_platform_ramdisk_sha256": sha256(input_dir / "vendor_ramdisk00"),
            "output_platform_ramdisk_sha256": sha256(device_tree / stock_relative),
            "supplied_module_count": module_count,
            "reason": "the supplied first-stage-only platform fragment cannot replace rodin BootControl/runtime; only its matching platform modules and metadata are overlaid",
        }
        profile["platform_ramdisk_sha256"] = sha256(device_tree / stock_relative)
        profile["recovery_modules"] = firmware_modules["module_metadata"]
        profile["recovery_module_sources"] = firmware_modules["source_partitions"]
        profile["patch_offsets"] = firmware_modules["patch_offsets"]
        profile["device_blob_manifest_sha256"] = manifest_sha
        profile_path.write_text(json.dumps(profile, indent=2) + "\n")


if __name__ == "__main__":
    main()
