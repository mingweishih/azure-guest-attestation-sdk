# Building azure-guest-attest

## Standard Build

```powershell
cargo build --release
```

## Static Build (Windows)

The `static` feature enables static CRT linking on Windows, producing a binary that doesn't require MSVC redistributables.

### MSVC Toolchain

```powershell
# Set RUSTFLAGS environment variable
$env:RUSTFLAGS="-Ctarget-feature=+crt-static"

# Build with static feature
cargo build --features static --release

# Clear the environment variable
Remove-Item Env:RUSTFLAGS
```

Or in a single command:

```powershell
$env:RUSTFLAGS="-Ctarget-feature=+crt-static"; cargo build --features static --release; Remove-Item Env:RUSTFLAGS
```

### GNU/MinGW Toolchain

The build script automatically handles static linking for GNU toolchain:

```powershell
cargo build --features static --release
```

No RUSTFLAGS needed - the build script will add `-static` and `-static-libgcc` automatically.

## Alternative: Permanent Configuration

To always use static linking for MSVC builds, uncomment the relevant line in `.cargo/config.toml`:

```toml
[target.'cfg(all(target_os = "windows", target_env = "msvc"))']
rustflags = ["-Ctarget-feature=+crt-static"]
```

Note: This affects **all** builds (even without the `static` feature), so you may prefer the environment variable approach for more control.

## Verification

The build script will emit warnings during compilation:

- **MSVC**: Reminds you to set RUSTFLAGS
- **GNU**: Confirms static linking is enabled

Test the binary:

```powershell
.\target\release\azure-guest-attest.exe --version
```

## Benefits of Static Builds

- No MSVC runtime dependencies (vcruntime140.dll, etc.)
- Self-contained binary suitable for deployment
- Easier distribution - works on systems without Visual Studio redistributables

## Trade-offs

- Slightly larger binary size
- Cannot benefit from shared runtime updates
- Each binary includes its own copy of the CRT
