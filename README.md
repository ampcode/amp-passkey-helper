# amp-passkey-helper

Runs one WebAuthn passkey ceremony with the user's phone over the FIDO hybrid transport, the
"use a phone or tablet" QR code flow that browsers offer. The calling app shows the QR code, the
user scans it with their phone, the phone proves it is nearby over Bluetooth, and the ceremony
runs through an encrypted tunnel. The phone uses the passkeys it already has: iCloud Keychain,
Google Password Manager, 1Password, and other passkey providers on the phone.

It exists because Electron on Linux has no passkey prompt. The [Amp](https://ampcode.com) Linux
app starts this helper for each passkey request. Nothing in it is specific to Amp.

It is built on [libwebauthn](https://github.com/linux-credentials/libwebauthn).

## Requirements

- Linux with a Bluetooth adapter, BlueZ, and D-Bus.
- Internet access on the computer and the phone, for the tunnel.
- A phone that supports hybrid sign-in: iOS 16 or later, or Android 9 or later with Google Play
  services.

## Protocol

The caller writes one JSON line to stdin:

```json
{"ceremony": "get", "origin": "https://example.com", "options": {"challenge": "…", "rpId": "example.com"}}
```

- `ceremony` is `get` (sign in with a passkey) or `create` (register a new one).
- `origin` is the page origin that the client data names.
- `options` is `PublicKeyCredentialRequestOptionsJSON` for `get` or
  `PublicKeyCredentialCreationOptionsJSON` for `create`, as `@simplewebauthn/browser` and
  `PublicKeyCredential.parseRequestOptionsFromJSON()` take them.

The helper then writes JSON lines to stdout:

```json
{"type": "qr", "url": "FIDO:/…", "svg": "<svg …>"}
{"type": "status", "status": "connecting"}
{"type": "result", "response": {"id": "…", "rawId": "…", "type": "public-key", "response": {…}}}
```

- `qr` comes first, with the QR code as a `FIDO:/` URL and as an SVG image.
- `status` lines report progress: `proximity-check`, `connecting`, `authenticating`, and
  `connected`.
- The last line is either `result`, with the credential as `AuthenticationResponseJSON` or
  `RegistrationResponseJSON`, or `error`, with the name of the `DOMException` a browser would
  throw (`NotAllowedError`, `NotSupportedError`, `InvalidStateError`, `SecurityError`, or
  `TypeError`) and a message. A `NotSupportedError` about Bluetooth also has a `reason`:
  `bluetooth-off` when the adapter is powered off, or `bluetooth-unavailable` when the computer
  has none. The exit status is 0 after `result` and 1 after `error`.

To cancel a ceremony, kill the process.

`amp-passkey-helper --version` prints `{"name": "amp-passkey-helper", "version": "…",
"protocol": 1}`. The protocol number changes only when a change would break callers of the
previous version.

### The caller checks the origin

The helper signs for whatever origin and relying party ID it is given, as a browser does for its
own pages. Before starting it, the caller must check what a browser checks: that the request comes
from a page on `origin`, and that the relying party ID is that origin's host or a registrable
parent domain of it. Without that check, a page could ask for another site's passkey. The helper
grants no new access by itself: any local program can already talk to a phone over Bluetooth.

## Try it

`amp-passkey-helper --demo` prints a QR code in the terminal and asks the phone to sign a random
challenge for `https://ampcode.com`. It shows whether Bluetooth, the tunnel, and the phone work on
a machine, without the calling app.

## Build

```sh
sudo apt install libdbus-1-dev libudev-dev pkg-config   # Debian and Ubuntu
cargo build --release
```

Tagged releases attach `amp-passkey-helper-<version>-<arch>-linux-gnu` binaries for `x86_64` and
`aarch64`, with SHA-256 checksums.

## License

LGPL-2.1-or-later, the same as libwebauthn. See [COPYING](COPYING).
