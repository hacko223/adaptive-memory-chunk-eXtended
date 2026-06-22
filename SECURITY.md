# Security Policy — C++ Accelerator Add-ons

This policy applies specifically to the `addons/` and `source code/` directories in this branch — the optional C++ accelerator modules for `amcx` (`amcx_accel`, `amcx_crc32`, `amcx_sha1`, `amcx_xor`).

## About these add-ons

These are **optional, native binaries** that `amcx` can load via `ctypes.CDLL` to speed up bypass scanning, CRC32 verification, SHA-1 mirroring, and XOR recovery. They are not required — without them, `amcx` falls back to its pure-Python implementation.

Because they are compiled binaries, they carry different risks than the rest of the project:

- A `.so` or `.dll` can execute arbitrary code with the same privileges as the Python process that loads it.
- Precompiled binaries cannot be inspected as easily as Python source.

## Supported Versions

| Component                  | Supported          |
| --------------------------- | ------------------- |
| Latest `source code/*.cpp`  | :white_check_mark: |
| Precompiled `.so` / `.dll`  | :warning: see below |

The `.cpp` source files are the only artifacts covered by ongoing security support. Precompiled binaries are provided for convenience only.

## Recommendation: build from source

**We strongly recommend compiling these add-ons yourself from the `.cpp` files** rather than using the precompiled `.so`/`.dll` binaries included in this branch, especially in production:

```bash
g++ -shared -fPIC -O2 -o amcx_accel.so amcx_accel.cpp      # Linux/Mac
x86_64-w64-mingw32-g++ -shared -O2 -o amcx_accel.dll amcx_accel.cpp   # Windows
```

Precompiled binaries are convenient for testing, but you should not trust a `.so`/`.dll` you didn't build yourself in any environment that matters. Verify the source first, then compile.

## Reporting a Vulnerability

If you find a vulnerability in any of the `.cpp` add-ons — a buffer overflow, an out-of-bounds read/write, an unsafe `memcpy`/`memset`, or any memory-safety issue — please report it privately through a [GitHub Security Advisory](https://github.com/hacko223/adaptive-memory-chunk-eXtended/security/advisories/new) rather than a public issue.

Include:

- Which add-on is affected (`amcx_accel`, `amcx_crc32`, `amcx_sha1`, or `amcx_xor`)
- A minimal C++ or Python/ctypes reproduction
- Compiler and platform used (e.g. `g++ 13.3.0` on Linux, or `mingw-w64` cross-compiled `.dll`)

### What to expect

- Initial response within **5 business days**.
- Accepted/declined decision within **14 days**.
- Memory-safety issues in native code are treated as **high priority** given the elevated risk of running unmanaged code — fixes will be prioritized over feature work on this branch.

## Scope

Covered: the four `.cpp` files in `source code/` and the loading logic that will integrate them into `amcx` (e.g. `accelerator_path` parameters once merged).

Not covered: the precompiled `.so`/`.dll` binaries as distributed (build them yourself), and any third-party fork or modification of these add-ons.
