# Adaptive Memory Chunk eXtended (amcx) — C++ Accelerator Add-ons

This branch adds **optional C++ accelerator modules** for `amcx`. The core library remains pure Python with zero dependencies — these add-ons are entirely opt-in and only used if you load them explicitly.

### *read [wiki](https://github.com/hacko223/adaptive-memory-chunk-eXtended/wiki) or see [changelog](https://hacko223.github.io/adaptive-memory-chunk-eXtended/) for more info*

## What's in this branch

```
addons/
├── linux/      → precompiled .so binaries
└── windows/    → precompiled .dll binaries

source code/
├── amcx_accel.cpp    → accelerates bypass scanning (detection.py)
├── amcx_crc32.cpp    → accelerates CRC32 verification (reader.py / writer.py)
├── amcx_sha1.cpp     → accelerates SHA-1 mirroring (mirror.py)
└── amcx_xor.cpp      → accelerates XOR parity/recovery (mirror.py)
```

## Installation

```bash
pip install amcx
```

## Building the add-ons yourself (recommended)

See [SECURITY.md](./SECURITY.md) for why you should build from source instead of using the precompiled binaries.

```bash
# Linux / Mac
g++ -shared -fPIC -O2 -o amcx_accel.so amcx_accel.cpp

# Windows (cross-compiled with mingw-w64, or compile natively with MSVC/MinGW)
x86_64-w64-mingw32-g++ -shared -O2 -o amcx_accel.dll amcx_accel.cpp
```

Repeat for `amcx_crc32.cpp`, `amcx_sha1.cpp`, and `amcx_xor.cpp`.

## Usage

```python
from amcx import chunk_memory

# Your code here
```

With an accelerator loaded (once integrated into the core library):

```python
from amcx import SmartMemory

memory = SmartMemory("chat.amcx", accelerator_path="./amcx_accel.so")
```

If the accelerator can't be loaded for any reason, `amcx` falls back to its pure-Python implementation automatically.

## License

This project is licensed under the GNU Lesser General Public License v3.0 or later (LGPL-3.0+).
See the [LICENSE](https://github.com/hacko223/adaptive-memory-chunk-eXtended/blob/f8390768395aa1d9dc210e9f25de0366684dfaf2/LICENSE) file for details.

## Author

- hacko223

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
