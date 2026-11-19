# Expert trajectory releases

Public download channel for signed builds of the expert trajectory collector.

- Each release is tagged `trajectory-v<version>` and contains, per macOS architecture, the notarized DMG, `mac-update-<arch>.json` and its Ed25519 signature `mac-update-<arch>.sig`.
- The menu bar app reads `releases/latest/download/mac-update-<arch>.json` without signing in, verifies the signature with the public key embedded in the app, then checks the DMG's SHA-256, Team ID, code signature and Gatekeeper before installing.
- Source code is not published here. Only files approved for distribution are uploaded.
