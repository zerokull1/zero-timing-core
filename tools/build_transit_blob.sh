#!/usr/bin/env bash
# ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_PATH="${1:-$ROOT_DIR/target/release/zero_transit_bundle.bin}"
mkdir -p "$(dirname "$OUT_PATH")"

TMP_DIR="$(mktemp -d /tmp/ztm_transit_blob.XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT

ROOT_DIR="$ROOT_DIR" TMP_DIR="$TMP_DIR" python3 - << 'PY'
import os
root, tmp = os.environ.get("ROOT_DIR"), os.environ.get("TMP_DIR")
l7 = open(f"{root}/src/l7_shield.rs").read()
l7 = l7.replace("#[inline(never)]", "#[inline(always)]")
l7 = l7.replace("#[no_mangle]\n", "").replace("#[unsafe(no_mangle)]\n", "")
open(f"{tmp}/l7_shield.rs", "w").write(l7)

src = open(f"{root}/src/lib.rs").read()
fn_part = src[src.index("#[repr(C, align(64))]\npub struct ZeroTransitState"):]
fn_part = fn_part.replace(
    "#[unsafe(no_mangle)]\npub unsafe extern \"C\" fn zero_bare_metal_transit_step(",
    "#[unsafe(no_mangle)]\n#[unsafe(link_section = \".text.zero_transit_bundle\")]\npub unsafe extern \"C\" fn zero_bare_metal_transit_step("
)
hdr = "#![no_std]\npub mod tsc { pub fn rdtsc_start() -> u64 { 0 } pub fn rdtsc_end() -> u64 { 0 } }\npub mod l7_shield;\n"
open(f"{tmp}/lib_bundle.rs", "w").write(hdr + fn_part)
PY

rustc --edition 2021 --crate-type=lib -O -C lto=fat -C codegen-units=1 -C opt-level=3 \
  -C panic=abort -C target-cpu=haswell --emit=obj "$TMP_DIR/lib_bundle.rs" -o "$TMP_DIR/bundle.o"

if readelf -r "$TMP_DIR/bundle.o" | grep -A 8 "zero_transit_bundle" | grep -q "R_X86_64_"; then
  echo "[FAIL] Relocations detected in .text.zero_transit_bundle" >&2
  exit 1
fi

objcopy -O binary --only-section=.text.zero_transit_bundle "$TMP_DIR/bundle.o" "$OUT_PATH"
nm -S --size-sort "$TMP_DIR/bundle.o" | grep zero_bare_metal_transit_step
sha256sum "$OUT_PATH"
