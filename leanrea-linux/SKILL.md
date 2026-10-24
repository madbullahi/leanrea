---
name: leanrea-linux
description: Reverse engineer shipped software on Linux with plain local CLI tools, no MCP needed. Covers ELF binaries and .so files, stripped C/C++, Go/Rust/.NET, Electron (AppImage, .deb, snap, flatpak), APKs, SQLite, pcaps, firmware/UEFI images and the machine's own ACPI/DMI tables. Use to explain how a feature works, extract versions/deps, compare builds, or rebuild a feature.
---

# leanrea-linux: fast path

You already know these tools. This file only lists the fastest command for each target, and the traps that differ from macOS.

## Rules
- Work on a copy: `cp --reflink=auto` (instant on btrfs/xfs, a normal copy elsewhere). GNU `cp -c` is NOT a clone, it means "preserve SELinux context".
- `$TMPDIR` is usually unset on Linux. Always write `R=${TMPDIR:-/tmp}/re`, and put each extraction in a new dir `$R/<name>`. Reuse an extraction if one exists.
- Route by `file -b T` and the magic bytes first (`xxd -l 64 T`). Run the cheapest inventory next. Only then disassemble or decompile.
- `rg` skips hidden and ignored files, and bundlers hide code (`.webpack/`, `.vite/`). Always search extracted trees with `rg -uu`.
- Never `cat` a big or minified file. Slice it: `rg -o '.{0,200}NEEDLE.{0,200}' F | head`. Dump a disassembly once to a file, then grep that file.
- Batch independent probes into ONE shell call with `;` and `echo '--- name'` markers. Cap every output with `head` or `-m`.
- Debian/Ubuntu default `awk` is mawk: no `strtonum`, no `gensub`. Do hex maths in bash (`$((16#ff))`) or call `gawk` explicitly.
- Answer from evidence. In the answer, mark each claim as **seen** (cite file:offset, address, symbol or string) or **inferred**. A fact you did not find is **unknown**, not "absent". Static reading is not observed execution.
- Root-only probes (`dmidecode`, `acpidump`, `flashrom`, `lspci -vvv`, `usbmon`) need `sudo`. Ask before running them, and never write to flash, EFI variables or the EC.
- A missing tool is not a blocker. Use the fallback in the same row, or `sudo apt install <x>` / `sudo dnf install <x>` if the user allows it.
- Turns cost more than bytes. Aim for 2–4 tool calls: one batched recon call, one or two targeted slices, then answer. Stop when every item you were asked has evidence.

## First move: one call each, paste and run
Native (ELF executable or .so):
```sh
T=./bin; D=${TMPDIR:-/tmp}/re/$(basename $T); mkdir -p $D; file -b $T; echo '--- HDR'; readelf -hW $T | rg 'Class|Machine|Type|Entry'; echo '--- NEEDED'; readelf -dW $T | rg 'NEEDED|RUNPATH|RPATH|SONAME'; echo '--- EXPORTS'; nm -D --defined-only $T | head -150; echo '--- IMPORTS'; nm -D --undefined-only $T | awk '{print $NF}' | tr '\n' ' '; echo; echo '--- STRINGS'; strings -a -n 5 $T | rg -v '^[_.$]|^GLIBC|^GCC' | head -400; objdump -d -M intel --no-show-raw-insn -C $T > $D/dis.txt; echo '--- FUNCS'; rg '^[0-9a-f]+ <.*>:$' $D/dis.txt | rg -v '@plt>' | head -150
```
On a stripped binary FUNCS shows only `<.text>`: there are no labels. Use the helpers below.

Helpers for stripped ELF (paste once per shell):
```sh
# string -> virtual address (+ section). objdump comments RIP-relative loads with an ADDRESS, not the string.
str2va(){ local off n a f s; off=$(grep -obUa -- "$2" "$1" | head -1 | cut -d: -f1); [ -n "$off" ] || return 1
  while read -r n a f s; do a=$((16#$a)); f=$((16#$f)); s=$((16#$s)); if (( a && off>=f && off<f+s )); then printf '%x %s\n' $((a+off-f)) "$n"; return; fi
  done < <(readelf -SW "$1" | sed -n 's/^ *\[ *[0-9]*\] *//p' | awk '$1!="NULL" && $3~/^[0-9a-f]+$/ {print $1,$3,$4,$5}'); }
# function starts: CET builds (Ubuntu, Fedora, Arch) begin every function with endbr64
fstarts(){ awk '/^[0-9a-f]+ <.*>:$/{sec=$2} sec!~/plt/ && /endbr64/{sub(":","",$1); print $1}' "$1"; }
fnof(){ local at=$((16#$2)) best=; for s in $(fstarts "$1"); do (( 16#$s <= at )) && best=$s; done; echo $best; }
trail(){ awk -v s="$2:" '$1==s{p=1} p&&/endbr64/&&$1!=s{exit} p' "$1" | rg 'call|lea .*#|cmp|test|ret'; }
```
Who uses a string: `VA=$(str2va $T 'needle' | cut -d' ' -f1); rg -n "# $VA <" $D/dis.txt`. Then read that function as a call trail: `trail $D/dis.txt $(fnof $D/dis.txt <ref-addr>)`. No `endbr64` at all (old or `-fcf-protection=none` builds): fall back to `r2 -qc 'aaa; axt @ str.X'` or Ghidra.

Electron (AppImage / .deb / snap / flatpak):
```sh
R=${TMPDIR:-/tmp}/re; A=$(find . $R -name app.asar 2>/dev/null | head -1); X=$R/asar; rm -rf $X; npx -y @electron/asar extract $A $X && jq '{name,version,main}' $X/package.json; find $X -path '*/node_modules' -prune -o -type f \( -name '*.js' -o -name '*.node' \) -print | head -60; ls ${A}.unpacked/node_modules 2>/dev/null; rg -uu -l --glob '!node_modules' 'exposeInMainWorld' $X
```
Locate the asar first: AppImage `./X.AppImage --appimage-extract` (extracts into `./squashfs-root`; or `unsquashfs -o $(./X.AppImage --appimage-offset) X.AppImage` without running it); `.deb` `dpkg-deb -x f.deb $R/deb`; `.rpm` `rpm2cpio f.rpm | cpio -idm`; snap `unsquashfs -d $R/snap f.snap`; installed flatpak `flatpak info --show-location ID`. The asar is usually under `resources/app.asar`, often in `opt/<App>/` or `usr/lib/<app>/`.

Go: `go version -m T` alone usually answers the question.

## Router
| Target (detect) | Fastest path |
|---|---|
| ELF overview (`file`: ELF) | `readelf -hlSW` (headers, segments, sections); `readelf -dW` (NEEDED, RUNPATH); `nm -D --defined-only` (exports) / `nm -D --undefined-only` (imports = the capability map); `readelf -nW` (build-id, ABI note); `readelf -p .comment T` (compiler versions). Hardening: `checksec --file=T` (or read `readelf -lW` for GNU_STACK/GNU_RELRO and `readelf -dW` for BIND_NOW). |
| Native code logic | `objdump -d -M intel --no-show-raw-insn -C T > dis.txt`. Unstripped: `rg -n '^[0-9a-f]+ <.*Name.*>:$' dis.txt`. Stripped: the helpers above. PLT calls are already named (`call 1110 <socket@plt>`), which is usually enough to read the protocol. Real pseudocode: Ghidra `analyzeHeadless $D p -import T -postScript DecompileAll.java -deleteProject` (set `MAXMEM=4G` in `support/analyzeHeadlessLaunch.properties` or the env on 8–16 GB machines), or `r2 -qc 'aaa; pdc @ sym.X' T`. Library calls at runtime: `ltrace -f -e 'socket+connect+open*' ./T`; syscalls: `strace -f -e trace=network,file -s 200 ./T`. Run untrusted binaries only in a VM or container. |
| PE / Windows (`file`: PE32) | `objdump -x T.exe` (imports, sections); `wrestool -l` / `wrestool -x` for resources; `pefile` in Python; `strings -el` for UTF-16LE. |
| Go (`.go.buildinfo` section) | `go version -m T` gives the toolchain, path, mod, deps and build flags in one call. Without Go: `strings -a T \| rg -m1 -A200 'Go buildinf'`. After `-ldflags='-s -w'`, `go tool nm` says "no symbols", but function names still live in `.gopclntab`: `strings -a T \| rg '^main\.'`, or `GoReSym T` (JSON, includes the full function table). |
| Rust | Deps (cargo-auditable): `cargo audit bin T`, or dump section `.dep-v0` (`objcopy -O binary --only-section=.dep-v0 T d.z`) and zlib-inflate it. Compiler: `strings -a T \| rg -o '/rustc/[0-9a-f]{40}' \| sort -u`. Crates: `strings -a T \| rg -o '[a-z0-9_-]+-[0-9]+\.[0-9]+\.[0-9]+/src' \| sort -u`. |
| .NET (`file`: Mono/.Net) | `ilspycmd -p -o X T.dll` (`dotnet tool install -g ilspycmd`), then `rg`. P/Invoke: `rg DllImport X`. Single-file bundles: extract with `sfextract` first. NativeAOT is native: use the ELF rows. |
| Python app (PyInstaller, Nuitka) | PyInstaller: `strings -a T \| rg -m1 'MEI\|pyi-'`, then `pyinstxtractor T` and decompile `.pyc` with `pycdc`. Nuitka is compiled C: use the ELF rows and grep the strings. |
| Web bundle / minified JS | Find `sourceMappingURL`. If the map has `sourcesContent`, dump it: `jq -r '.sources[]'`. Webpack: grep the module ids, then slice around the hit. Pretty-print: `npx -y prettier --parser babel F > F.pretty.js`. |
| Electron (asar found) | Entry: `jq .main X/package.json`. Surface: `rg -n -o '.{0,120}(ipcMain\.(handle\|handleOnce\|on\|once)\|ipcRenderer\.(invoke\|send\|sendSync\|on)\|contextBridge\.exposeIn(Main\|Isolated)World\|webPreferences\|preload:\|nodeIntegration\|contextIsolation\|sandbox\|\.node\b).{0,160}' -uu X --glob '!node_modules'`. Wrapped IPC channels: `rg -uu -o '"[a-z]+:[a-z0-9:-]+"' X/<main> \| sort -u`. Fuses: `npx -y @electron/fuses read --app <path-to-electron-binary>`. Native addons in `app.asar.unpacked/` are ELF `.so` files: use the ELF rows. |
| Hermes / bytenode | Hermes magic `c6 1f bc 03`: use `hermes-dec`. `.jsc` (bytenode) cannot be decompiled: use strings and runtime hooks. |
| Android APK | `jadx -d X --show-bad-code a.apk`, then `rg`. Manifest/resources only: `apktool d --no-src -o X a.apk`. `lib/*/libflutter.so` means Flutter (Dart AOT: `blutter`); `libhermes.so` means React Native (Hermes row). |
| Flutter snapshot hash | In `libapp.so`, find magic `f5 f5 dc dc`; the 32 hex chars at +20 are the snapshot hash. Map it to a Dart version. |
| WASM | `wasm-objdump -x`, `wasm2wat`, `wasm-decompile` (WABT). |
| SQLite | Copy the db, plus `-wal` if present. `sqlite3 'file:C?mode=ro' '.schema'`, then `SELECT * FROM t LIMIT 20`. |
| pcap / HAR | `tshark -r C -q -z conv,tcp`; `tshark -r C -T fields -e dns.qry.name -e tls.handshake.extensions_server_name -e http.request.full_uri \| sort -u`. HAR: `jq -r '.log.entries[].request \| .method+" "+.url'`. |
| USB device protocol | `lsusb -v -d VID:PID` (descriptors, endpoints, HID). Capture: `sudo modprobe usbmon; sudo tshark -i usbmon<bus> -w u.pcapng`, toggle one feature per capture, then `tshark -r u.pcapng -T fields -e usb.capdata -e usbhid.data` and diff. Replay with `pyusb` / `hidapi`. |
| Firmware blob (router, IoT) | `binwalk -e F` or `unblob -e X F`. SquashFS: `unsquashfs`. JFFS2: `jefferson`. Then route each extracted binary through this table. Run foreign-arch userland: `qemu-<arch>-static -L X/rootfs X/rootfs/bin/busybox` (install `qemu-user-static`). |
| UEFI / BIOS image | Vendor update ISO: `geteltorito -o b.img f.iso`, then mount or `7z x`. Intel flash layout: `ifdtool -d F` (regions, locks), `ifdtool -x F` (split regions). ME: `me_cleaner -c F` (check only). Volumes and modules: `UEFIExtract F all`, then `rg -l` across the dump tree; Setup strings: `strings -el` on the Setup DXE body. |
| This machine's firmware tables | `sudo dmidecode -t system,bios,baseboard,processor,memory`; `sudo acpidump > acpi.dat; acpixtract -a acpi.dat; iasl -d *.dat`, then `rg -n 'OperationRegion\|Field \(ECOR\|Method \(_Q' dsdt.dsl` (EC registers, hotkey `_Qxx` events). PCI: `lspci -nnk` (driver bound to each device), `sudo lspci -vvv -s BDF`. Flash: `sudo flashrom -p internal` (read-only probe; it reports protected regions). |
| Kernel modules | `modinfo M` (params, aliases, firmware files); `nm --defined-only M.ko`; `strings -a M.ko \| rg -i 'param\|firmware'`. Loaded: `lsmod`, `/sys/module/M/parameters/`. |
| Website | `curl -sL URL` for the HTML and script srcs, then fetch the JS and slice it. Runtime: headless browser with a network log (Playwright `page.on('request')`) or Chrome `--remote-debugging-port`. |
| Running process | `cat /proc/PID/maps` (loaded libs and regions); `ls -l /proc/PID/fd`; `ss -xp \| rg PID` (unix sockets); `gdb -p PID`; `strace -f -p PID`; `perf trace`. Electron main: `--inspect` only if the RunAsNode/inspect fuses allow it. Android: `adb logcat`, `frida -U -f pkg -l hook.js`. |

## Speed patterns
- Strings and imports first. On a small binary, `nm -D --undefined-only` + `strings` + the export list usually answer "what does it do" with no disassembly.
- `strings -n 6` hides short protocol words like `FOCUS\n`. If the protocol is missing, rerun with `-n 4` and filter: `strings -a -n 4 T | rg -x '[A-Z_]{3,}'`.
- To find who uses a string on a stripped ELF: `str2va`, then grep `# <va> <` in `dis.txt`, then `fnof` + `trail`. The PLT names in the trail usually give the protocol directly (`socket`, `bind`, `connect`, `write`, `getsockopt(SO_PEERCRED)`).
- For JS, go from the native/JS boundary inward: native call, then its caller class, then the IPC registration, then the renderer/preload.
- Comparing versions: diff the inventories (`nm -D`, the module list, `go version -m`, `readelf -dW`) before you diff any code.
- Rebuilding: write the minimal reimplementation, then test it against the original (same inputs, same outputs).

## Install (only on request)
Debian/Ubuntu: `sudo apt install binutils file ripgrep jq radare2 binwalk squashfs-tools p7zip-full acpica-tools dmidecode flashrom pciutils usbutils tshark ltrace strace gdb wabt sqlite3 qemu-user-static`. Fedora: `sudo dnf install` with `acpica-tools`, `wireshark-cli`, the rest the same. Also: `npm i -g @electron/asar` · `pipx install unblob` · `cargo install cargo-audit` · `dotnet tool install -g ilspycmd` · Ghidra from its GitHub release (needs a JDK 21). `ifdtool` builds from coreboot: `make -C util/ifdtool`.
