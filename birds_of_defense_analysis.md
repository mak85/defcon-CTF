# Birds of Defense - Analysis Summary

## Binary Overview
- **File**: ELF 64-bit LSB pie executable, x86-64, stripped (no symbols)
- **Compiler**: GCC 15.2.0 (Ubuntu 15.2.0-4ubuntu4)
- **Type**: C++ SDL2/OpenGL tower defense game with 10 waves and 8 enemy types
- **Build ID**: dafb397fd85953fabeb8d88594ce1034bdb82e82

## Key Strings Found
- Game messages: "BIRDS OF DEFENSE", "VICTORY!", "ALL WAVES DONE!", "GAME OVER", "The Birds have defended the nest"
- Enemy types: Moth, Beetle, Wasp, Caterpillar, Locust, Spider, Mantis (final boss "Praying Mantis")
- Bird towers: Eagle, Parrot, Heron, Falcon, Penguin, Flamingo, Toucan
- File operations: "proc_tmp.txt" (scratch file), "/proc/self/status" + "TracerPid:" (anti-debug)
- Hash labels: "digit_sum=", "combined_hash=", "hash_a=", "rev_a=", "acc=", "result="

## Cryptographic Findings
- **NO AES S-box** (no 0x63, 0x7c, 0x77, 0x7b... constants)
- **NO AES-NI instructions** (aesenc, aesdec, etc.)
- **NO SHA constants** (0x6a09e667, 0xbb67ae85, etc.)
- **NO libcrypto/libgcrypt symbols** (libgcrypt only loaded transitively via SDL2_mixer audio)
- **NO embedded ciphertext blobs** in .rodata or .data sections
- **Has djb2 hash** at multiple locations (0x1505 init, shift 5, add char)

## Anti-Debug
The binary reads `/proc/self/status` and parses `TracerPid:` line. If the TracerPid > 0
(meaning a debugger like strace/gdb is attached), `main()` exits early at 0x7aaf.

## Critical Function at 0x1b5f0
This is a complex 6000+ byte function that:
1. Opens `proc_tmp.txt` for writing, writes input int %r12d (arg3)
2. Appends: `\n`, %ecx (arg4), `hash_a=N`, `rev_a=N` (newlines between)
3. Opens for reading, reads 2 ints (the values just written back)
4. Appends: `digit_sum=N`, `combined_hash=N`, `acc=D` (double)
5. Appends: `result=N`
6. More file operations (read, hash, append)

The function uses magic constants for division-by-10000/100/10 (typical itoa optimization)
and djb2 hashing throughout.

## Call Chain
- `0x1b5f0` (write-to-proc_tmp.txt) is called by `0x1d4e0`
- `0x1d4e0` is called by `0xcb50` 
- `0xcb50` reads entity fields at offsets +0x08, +0x0c, +0x10
- These are called during gameplay when entities act

## Limitations Encountered
1. **No GPU available** - SDL_GL_CreateContext fails on the test environment
2. **GL stubs make game stuck at title screen** - waits for input events
3. **Anti-debug prevents tracing with strace/gdb** - would need to bypass

## Game State Machine (at 0x305c8)
- State 0: title screen / controller select
- State 2: gameplay
- State 4: post-game or transition
- State > 4: end state

## What the Challenge Likely Requires
The challenge says: "Better keep your AES GCM handy in the end!" - this strongly implies:
1. Play through all 10 waves to defeat Praying Mantis boss
2. Get the final game state values (likely written to proc_tmp.txt or displayed)
3. Combine values like `hash_a` (8 bytes) + `combined_hash` (8 bytes) = 16-byte AES-128 key
4. The IV/nonce and ciphertext might be derived similarly or extracted from somewhere
5. Use AES-GCM to decrypt the flag

## Recommendation
This challenge requires the binary to be RUN in a real OpenGL-capable environment
(physical GPU or accelerated VM). The flag is computed dynamically based on game state
after winning, and cannot be extracted by static analysis alone.
