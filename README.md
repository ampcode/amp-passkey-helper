# amp-passkey-helper

Runs one WebAuthn passkey ceremony with the user's phone or a USB security key, the way a browser's
passkey prompt does.

- **Phone:** the FIDO hybrid transport, the "use a phone or tablet" QR code flow that browsers
  offer. The calling app shows the QR code, the user scans it with their phone, the phone proves
  it is nearby over Bluetooth, and the ceremony runs through an encrypted tunnel. The phone uses
  the passkeys it already has, such as iCloud Keychain, Google Password Manager, or another passkey
  provider on the phone.
- **Security key:** at the same time, the helper watches for USB security keys, such as a
  YubiKey, and blinks each one. A key joins when the user touches it, so a key left plugged in
  does not take over from the phone. The helper asks the caller for the key's PIN when it needs
  one.

It exists because Electron on Linux has no passkey prompt. The [Amp](https://ampcode.com) Linux
app starts this helper for each passkey request. Nothing in it is specific to Amp.

It is built on [libwebauthn](https://github.com/linux-credentials/libwebauthn).

## Requirements

- For the phone: Linux with a Bluetooth adapter, BlueZ, and D-Bus; internet access on the
  computer and the phone, for the tunnel; and a phone that supports hybrid sign-in: iOS 16 or
  later, or Android 9 or later with Google Play services.
- For a security key: read and write access to its `/dev/hidraw*` device, the same access
  browsers and OpenSSH need. systemd's udev rules give it to the logged-in user on current
  distributions.

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
{"type": "status", "status": "security-key"}
{"type": "pin", "attemptsLeft": 8}
{"type": "status", "status": "touch-key"}
{"type": "result", "response": {"id": "…", "rawId": "…", "type": "public-key", "response": {…}}}
```

- First, `qr` with the QR code as a `FIDO:/` URL and as an SVG image when Bluetooth is ready, or
  `{"type": "phone-unavailable", "reason": …}` when it is not: `bluetooth-off` when the adapter is
  powered off, or `bluetooth-unavailable` when the computer has none. Then only a security key can
  finish the ceremony.
- `status` lines report progress. From the phone: `proximity-check`, `connecting`,
  `authenticating`, and `connected`. From a security key: `security-key` once the user touched it
  to pick it, then `touch-key` when it wants another touch and `uv-retry` when its fingerprint
  check failed.
- `pin` asks for the security key's PIN, with the tries left when the key reports them. Answer with
  a line on stdin, `{"pin": "…"}`. A wrong PIN asks again.
- The last line is either `result`, with the credential as `AuthenticationResponseJSON` or
  `RegistrationResponseJSON`, or `error`, with the name of the `DOMException` a browser would
  throw (`NotAllowedError`, `InvalidStateError`, `SecurityError`, or `TypeError`) and a message.
  The exit status is 0 after `result` and 1 after `error`.

Keep stdin open for the whole ceremony: closing it cancels the ceremony. To cancel, kill the
process or close stdin.

`amp-passkey-helper --version` prints `{"name": "amp-passkey-helper", "version": "…",
"protocol": 2}`. The protocol number changes only when a change would break callers of the
previous version. Protocol 2 added security keys and the PIN reply on stdin.

### The caller checks the origin

The helper signs for whatever origin and relying party ID it is given, as a browser does for its
own pages. Before starting it, the caller must check what a browser checks: that the request comes
from a page on `origin`, and that the relying party ID is that origin's host or a registrable
parent domain of it. Without that check, a page could ask for another site's passkey. The helper
grants no new access by itself: any local program can already talk to a phone over Bluetooth, or
to a security key over USB.

## Try it

`amp-passkey-helper --demo` prints a QR code in the terminal and asks the phone, or a security key
you touch, to sign a random challenge for `https://ampcode.com`. Type the key's PIN when it asks.
It shows whether Bluetooth, the tunnel, the phone, and security keys work on a machine, without the
calling app.

## Build

```sh
sudo apt install libdbus-1-dev libudev-dev pkg-config   # Debian and Ubuntu
cargo build --release
```

Tagged releases attach `amp-passkey-helper-<version>-<arch>-linux-gnu` binaries for `x86_64` and
`aarch64`, with SHA-256 checksums.

## License

LGPL-2.1-or-later, the same as libwebauthn. See [COPYING](COPYING).
