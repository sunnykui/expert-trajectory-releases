# Expert trajectory releases

Public download channel for builds of the expert trajectory collector.

- Each release is tagged `trajectory-v<version>` and contains:
  - **macOS (arm64)**: Notarized Developer ID DMG (`one2x-traj-<version>-macos-arm64.dmg`), `mac-update-arm64.json`, and its Ed25519 signature `mac-update-arm64.sig`.
  - **Windows (x86_64)**: Single-file installer (`one2x-traj-setup-<version>.exe`), `windows-update-x86_64.json`, and its Ed25519 signature `windows-update-x86_64.sig`.
- **Windows first-time install bootstrap (`windows-install.ps1`)**: Verifies the Ed25519 signature and SHA-256 against the pinned release public key and runs `--first-install` without browser Mark-of-the-Web prompts on standard Windows 10/11 machines:
  ```powershell
  powershell -NoProfile -ExecutionPolicy Bypass -File .\windows-install.ps1
  ```
  (Pass `-Proxy http://127.0.0.1:<port>` if a local HTTP/HTTPS proxy is required.)
- Installed macOS menu bar and Windows tray apps read `releases/latest/download/<platform>-update-<arch>.json` without signing in, verify the Ed25519 signature with the embedded public key, and check SHA-256 (plus Apple Team ID / Gatekeeper on macOS) before updating.
- Source code is not published here. Only files approved for distribution are uploaded.
