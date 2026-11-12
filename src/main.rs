//! Runs one WebAuthn passkey ceremony with the user's phone or a USB security key, for apps whose
//! web view has no passkey prompt, such as Electron on Linux (the Amp Linux app starts this helper
//! for each ceremony). The phone uses the FIDO hybrid transport: the caller shows a QR code, the
//! phone scans it and proves it is nearby over Bluetooth, and the ceremony runs through an
//! encrypted tunnel. At the same time the helper watches for USB security keys; a key joins once
//! the user touches it, so a key left plugged in does not take over from the phone.
//!
//! Protocol 2: the first JSON line on stdin is `{"ceremony":"get"|"create","origin":"https://…",
//! "options":{…}}`, with the server's options as `@simplewebauthn/browser` takes them. The helper
//! writes JSON lines to stdout:
//!
//! - `{"type":"qr","url":"FIDO:/…","svg":"<svg…>"}` when Bluetooth is ready, or
//!   `{"type":"phone-unavailable","reason":"bluetooth-off"|"bluetooth-unavailable"}` when it is
//!   not, in which case only a security key can finish the ceremony.
//! - Any number of `{"type":"status","status":…}`: `proximity-check`, `connecting`,
//!   `authenticating`, and `connected` from the phone; `security-key` once the user touched a key,
//!   then `touch-key` when it wants another touch and `uv-retry` when its fingerprint check failed.
//! - `{"type":"pin","attemptsLeft":n|null}` when the key needs its PIN. The caller answers with a
//!   stdin line `{"pin":"…"}`; closing stdin instead cancels the ceremony.
//! - Last, either `{"type":"result","response":{…}}` with the credential JSON, or
//!   `{"type":"error","name":…,"message":…}` with the DOM exception name a browser would throw.
//!
//! The caller cancels a ceremony by killing the process.
//!
//! The caller owns the origin check: this helper signs for whatever origin it is given, as a
//! browser does for its own pages. Any local process could already reach the phone over
//! Bluetooth, or a security key over USB, itself, so the helper grants nothing new.
//!
//! `amp-passkey-helper --version` prints `{"name":…,"version":…,"protocol":2}`, so a caller can
//! refuse a helper whose protocol it does not speak.
//!
//! `amp-passkey-helper --demo` signs a random challenge for https://ampcode.com and prints the QR
//! code to the terminal, to try the phone or a security key without the app.

use std::collections::HashMap;
use std::io::Read;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use btleplug::api::{Central as _, CentralState, Manager as _};
use btleplug::platform::Manager;

use libwebauthn::UvUpdate;
use libwebauthn::ops::webauthn::{
	GetAssertionRequest, JsonFormat, MakeCredentialRequest, OriginValidation, RequestOrigin,
	RequestSettings, WebAuthnIDLResponse as _,
};
use libwebauthn::proto::CtapError;
use libwebauthn::transport::hid::channel::HidChannelHandle;
use libwebauthn::transport::hid::device::HidBackendDevice;
use libwebauthn::transport::hid::{HidDevice, list_devices};
use libwebauthn::transport::hybrid::channel::{HybridUxUpdate, PxpUpdate};
use libwebauthn::transport::hybrid::qr_code_device::{
	PxpQrCodeDevice, PxpTransports, QrCodeOperationHint,
};
use libwebauthn::transport::{Channel as _, ChannelSettings, Device as _};
use libwebauthn::webauthn::{WebAuthn, WebAuthnError};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, BufReader, Lines, Stdin};
use tokio::sync::{Mutex, mpsc};

/// The version of the stdin and stdout protocol in the module documentation. Raise it when a change
/// would break a caller written for the previous version; `--version` reports it. Version 2 added
/// security keys, whose PIN the caller answers on stdin.
const PROTOCOL_VERSION: u32 = 2;

struct Request {
	create: bool,
	origin: String,
	options: Value,
}

/// A failure, as the DOM exception a browser would reject `navigator.credentials` with.
struct Failure {
	name: &'static str,
	message: String,
}

impl Failure {
	fn new(name: &'static str, message: impl Into<String>) -> Self {
		Self {
			name,
			message: message.into(),
		}
	}
}

/// Why the phone cannot be used: `bluetooth-off` or `bluetooth-unavailable`, or None when a
/// Bluetooth adapter is powered on. libwebauthn checks only that one exists, and with it powered
/// off the phone's proximity check would wait until the caller gives up.
async fn bluetooth_problem() -> Option<&'static str> {
	let Ok(manager) = Manager::new().await else {
		return Some("bluetooth-unavailable");
	};
	let adapters = match manager.adapters().await {
		Ok(adapters) if !adapters.is_empty() => adapters,
		_ => return Some("bluetooth-unavailable"),
	};
	for adapter in adapters {
		if matches!(adapter.adapter_state().await, Ok(CentralState::PoweredOn)) {
			return None;
		}
	}
	Some("bluetooth-off")
}

fn emit(event: Value) {
	println!("{event}");
}

type StdinLines = Lines<BufReader<Stdin>>;

async fn read_request(lines: &mut StdinLines) -> Result<Request, Failure> {
	let line = lines
		.next_line()
		.await
		.map_err(|error| Failure::new("TypeError", format!("Could not read the request: {error}")))?
		.ok_or_else(|| Failure::new("TypeError", "No request on stdin"))?;
	let request: Value = serde_json::from_str(&line)
		.map_err(|error| Failure::new("TypeError", format!("The request is not JSON: {error}")))?;
	let create = match request["ceremony"].as_str() {
		Some("get") => false,
		Some("create") => true,
		_ => return Err(Failure::new("TypeError", "Unknown ceremony")),
	};
	let origin = request["origin"]
		.as_str()
		.ok_or_else(|| Failure::new("TypeError", "The request has no origin"))?
		.to_owned();
	Ok(Request {
		create,
		origin,
		options: request["options"].clone(),
	})
}

/// Forwards the PINs the caller writes on stdin after the request, as `{"pin":"…"}` lines, or as
/// plain lines typed into `--demo`. When stdin closes, the caller is gone, so this cancels the
/// ceremony (except in `--demo`) rather than leave a security key waiting for a touch.
fn read_pins(
	mut lines: StdinLines,
	demo: bool,
	done: mpsc::Sender<Result<Value, Failure>>,
) -> mpsc::UnboundedReceiver<String> {
	let (sender, receiver) = mpsc::unbounded_channel();
	tokio::spawn(async move {
		while let Ok(Some(line)) = lines.next_line().await {
			let pin = if demo {
				Some(line)
			} else {
				serde_json::from_str::<Value>(&line)
					.ok()
					.and_then(|message| message["pin"].as_str().map(str::to_owned))
			};
			if let Some(pin) = pin {
				let _ = sender.send(pin);
			}
		}
		if !demo {
			let failure = Failure::new("NotAllowedError", "The passkey request was canceled");
			let _ = done.send(Err(failure)).await;
		}
	});
	receiver
}

fn demo_request() -> Request {
	let mut challenge = [0u8; 32];
	std::fs::File::open("/dev/urandom")
		.and_then(|mut random| random.read_exact(&mut challenge))
		.expect("read /dev/urandom");
	let challenge: String = challenge.iter().map(|byte| format!("{byte:02x}")).collect();
	Request {
		create: false,
		origin: "https://ampcode.com".into(),
		options: json!({
			"challenge": challenge,
			"rpId": "ampcode.com",
			"userVerification": "preferred",
			"timeout": 120000,
		}),
	}
}

/// The ceremony, prepared once and run on whichever authenticator the user picks.
enum Ceremony {
	Create(MakeCredentialRequest),
	Get(GetAssertionRequest),
}

/// `device` names the authenticator in messages: "phone" or "security key".
fn failure_for_ceremony(error: WebAuthnError<impl std::fmt::Display>, device: &str) -> Failure {
	match error {
		WebAuthnError::Ctap(CtapError::CredentialExcluded) => Failure::new(
			"InvalidStateError",
			format!("This {device} already has a passkey for this account"),
		),
		WebAuthnError::Ctap(CtapError::NoCredentials) => Failure::new(
			"NotAllowedError",
			format!("This {device} has no passkey for this account"),
		),
		WebAuthnError::Ctap(CtapError::PINBlocked) => Failure::new(
			"NotAllowedError",
			"This security key's PIN is blocked after too many wrong tries",
		),
		error => Failure::new("NotAllowedError", error.to_string()),
	}
}

/// Runs the ceremony on `channel` and returns the credential JSON. A wrong PIN or a failed
/// fingerprint asks again, as the key allows.
async fn perform<C: WebAuthn>(
	channel: &mut C,
	ceremony: &Ceremony,
	device: &str,
) -> Result<Value, Failure> {
	loop {
		let response = match ceremony {
			Ceremony::Create(request) => {
				channel
					.webauthn_make_credential(request)
					.await
					.map(|response| {
						response
							.to_json_string(request, JsonFormat::Minified)
							.map_err(|error| error.to_string())
					})
			}
			Ceremony::Get(request) => {
				channel
					.webauthn_get_assertion(request)
					.await
					.map(|response| {
						// The authenticator lets the user pick one passkey, so it returns one assertion.
						match response.assertions.first() {
							Some(assertion) => assertion
								.to_json_string(request, JsonFormat::Minified)
								.map_err(|error| error.to_string()),
							None => Err(format!("The {device} returned no passkey")),
						}
					})
			}
		};
		let json = match response {
			Err(WebAuthnError::Ctap(CtapError::PINInvalid | CtapError::UVInvalid)) => continue,
			Err(error) => return Err(failure_for_ceremony(error, device)),
			Ok(json) => json.map_err(|message| Failure::new("NotAllowedError", message))?,
		};
		return serde_json::from_str(&json)
			.map_err(|error| Failure::new("NotAllowedError", error.to_string()));
	}
}

/// Shows the QR code and runs the ceremony with the phone.
async fn run_phone(
	ceremony: Arc<Ceremony>,
	create: bool,
	demo: bool,
	done: mpsc::Sender<Result<Value, Failure>>,
) {
	let hint = if create {
		QrCodeOperationHint::MakeCredential
	} else {
		QrCodeOperationHint::GetAssertionRequest
	};
	let result = async {
		let mut device = PxpQrCodeDevice::new_transient(hint, PxpTransports::CloudAssistedOrLocal)
			.map_err(|error| Failure::new("NotAllowedError", error.to_string()))?;
		let url = device.qr_code.to_string();
		let code = qrcode::QrCode::new(url.as_bytes())
			.map_err(|error| Failure::new("NotAllowedError", error.to_string()))?;
		if demo {
			let image = code
				.render::<qrcode::render::unicode::Dense1x2>()
				.dark_color(qrcode::render::unicode::Dense1x2::Light)
				.light_color(qrcode::render::unicode::Dense1x2::Dark)
				.build();
			eprintln!(
				"{image}\nScan this with your phone's camera and keep the phone near this computer, \
				 or touch a security key."
			);
		}
		emit(json!({
			"type": "qr",
			"url": url,
			"svg": code.render::<qrcode::render::svg::Color>().min_dimensions(240, 240).build(),
		}));

		let mut channel = device
			.channel(ChannelSettings::default())
			.await
			.map_err(|error| Failure::new("NotAllowedError", error.to_string()))?;
		let mut updates = channel.get_ux_update_receiver();
		tokio::spawn(async move {
			while let Ok(update) = updates.recv().await {
				let status = match update {
					HybridUxUpdate::PxpUpdate(PxpUpdate::ProximityCheck) => "proximity-check",
					HybridUxUpdate::PxpUpdate(PxpUpdate::Connecting) => "connecting",
					HybridUxUpdate::PxpUpdate(PxpUpdate::Authenticating) => "authenticating",
					HybridUxUpdate::PxpUpdate(PxpUpdate::Connected) => "connected",
					HybridUxUpdate::PxpUpdate(PxpUpdate::Error(_)) => continue,
					// The phone verifies the user itself; a PIN prompt here would be for a security
					// key, which this transport never reaches.
					HybridUxUpdate::UvUpdate(UvUpdate::PinRequired(update)) => {
						update.cancel();
						continue;
					}
					HybridUxUpdate::UvUpdate(_) => continue,
				};
				emit(json!({ "type": "status", "status": status }));
			}
		});
		let result = perform(&mut channel, &ceremony, "phone").await;
		channel.close().await;
		result
	}
	.await;
	let _ = done.send(result).await;
}

/// The USB security keys the helper is talking to, by hidraw path, so it starts one task per key
/// and can stop the others' blinking once the user picks one.
#[derive(Default)]
struct SecurityKeys {
	handles: Mutex<HashMap<String, Option<HidChannelHandle>>>,
	chosen: AtomicBool,
}

impl SecurityKeys {
	async fn cancel_all_except(&self, keep: &str) {
		for (path, handle) in self.handles.lock().await.iter() {
			if path != keep
				&& let Some(handle) = handle
			{
				handle.cancel_ongoing_operation().await;
			}
		}
	}
}

/// Watches for USB security keys for the rest of the ceremony and starts each new one.
async fn watch_security_keys(
	demo: bool,
	keys: Arc<SecurityKeys>,
	ceremony: Arc<Ceremony>,
	pins: Arc<Mutex<mpsc::UnboundedReceiver<String>>>,
	done: mpsc::Sender<Result<Value, Failure>>,
) {
	loop {
		for device in list_devices().await.unwrap_or_default() {
			let HidBackendDevice::HidApiDevice(info) = &device.backend;
			let path = info.path().to_string_lossy().into_owned();
			if keys.handles.lock().await.contains_key(&path) {
				continue;
			}
			keys.handles.lock().await.insert(path.clone(), None);
			tokio::spawn(run_security_key(
				demo,
				device,
				path,
				keys.clone(),
				ceremony.clone(),
				pins.clone(),
				done.clone(),
			));
		}
		tokio::time::sleep(Duration::from_millis(500)).await;
	}
}

/// Blinks one security key until the user touches it, then runs the ceremony on it. A key that
/// fails before its touch, such as one unplugged, is forgotten so it starts again when it returns.
async fn run_security_key(
	demo: bool,
	mut device: HidDevice,
	path: String,
	keys: Arc<SecurityKeys>,
	ceremony: Arc<Ceremony>,
	pins: Arc<Mutex<mpsc::UnboundedReceiver<String>>>,
	done: mpsc::Sender<Result<Value, Failure>>,
) {
	let Ok(mut channel) = device.channel(ChannelSettings::default()).await else {
		keys.handles.lock().await.remove(&path);
		return;
	};
	keys.handles
		.lock()
		.await
		.insert(path.clone(), Some(channel.get_handle()));
	let touched = channel
		.blink_and_wait_for_user_presence(Duration::from_secs(300))
		.await;
	if !matches!(touched, Ok(true)) {
		channel.close().await;
		keys.handles.lock().await.remove(&path);
		return;
	}
	if keys.chosen.swap(true, Ordering::SeqCst) {
		channel.close().await;
		return;
	}
	keys.cancel_all_except(&path).await;
	emit(json!({ "type": "status", "status": "security-key" }));

	let mut updates = channel.get_ux_update_receiver();
	tokio::spawn(async move {
		while let Ok(update) = updates.recv().await {
			match update {
				UvUpdate::PresenceRequired => {
					emit(json!({ "type": "status", "status": "touch-key" }));
				}
				UvUpdate::UvRetry { .. } => {
					emit(json!({ "type": "status", "status": "uv-retry" }));
				}
				UvUpdate::PinRequired(update) => {
					emit(json!({ "type": "pin", "attemptsLeft": update.attempts_left }));
					if demo {
						eprintln!("Type the security key's PIN and press Enter.");
					}
					match pins.lock().await.recv().await {
						Some(pin) => {
							let _ = update.send_pin(&pin);
						}
						None => update.cancel(),
					}
				}
				// The site requires a PIN and the key has none. Setting one is for the key's own
				// tools, not a sign-in prompt.
				UvUpdate::PinNotSet(update) => update.cancel(),
			}
		}
	});
	let result = perform(&mut channel, &ceremony, "security key").await;
	channel.close().await;
	let _ = done.send(result).await;
}

async fn run(request: Request, lines: StdinLines, demo: bool) -> Result<Value, Failure> {
	let origin: RequestOrigin = request
		.origin
		.as_str()
		.try_into()
		.map_err(|_| Failure::new("SecurityError", "Invalid origin"))?;
	let settings = RequestSettings {
		origin: OriginValidation::Trust,
	};
	let options = request.options.to_string();
	let ceremony = Arc::new(if request.create {
		Ceremony::Create(
			MakeCredentialRequest::prepare(&origin, &options, &settings)
				.await
				.map_err(|error| Failure::new("TypeError", error.to_string()))?,
		)
	} else {
		Ceremony::Get(
			GetAssertionRequest::prepare(&origin, &options, &settings)
				.await
				.map_err(|error| Failure::new("TypeError", error.to_string()))?,
		)
	});

	let (done, mut results) = mpsc::channel(4);
	let pins = read_pins(lines, demo, done.clone());
	match bluetooth_problem().await {
		None => {
			tokio::spawn(run_phone(
				ceremony.clone(),
				request.create,
				demo,
				done.clone(),
			));
		}
		Some(reason) => {
			if demo {
				eprintln!("The phone is unavailable ({reason}). Touch a security key.");
			}
			emit(json!({ "type": "phone-unavailable", "reason": reason }));
		}
	}
	let keys = Arc::new(SecurityKeys::default());
	tokio::spawn(watch_security_keys(
		demo,
		keys.clone(),
		ceremony,
		Arc::new(Mutex::new(pins)),
		done,
	));
	let result = results
		.recv()
		.await
		.unwrap_or_else(|| Err(Failure::new("NotAllowedError", "The passkey request ended")));
	// Stop any key still blinking, so it does not wait for a touch after the helper exits.
	keys.cancel_all_except("").await;
	result
}

#[tokio::main]
async fn main() {
	if std::env::args().any(|argument| argument == "--version") {
		emit(json!({
			"name": env!("CARGO_PKG_NAME"),
			"version": env!("CARGO_PKG_VERSION"),
			"protocol": PROTOCOL_VERSION,
		}));
		return;
	}
	let demo = std::env::args().any(|argument| argument == "--demo");
	let mut lines = BufReader::new(tokio::io::stdin()).lines();
	let request = if demo {
		Ok(demo_request())
	} else {
		read_request(&mut lines).await
	};
	let result = match request {
		Ok(request) => run(request, lines, demo).await,
		Err(failure) => Err(failure),
	};
	match result {
		Ok(response) => emit(json!({ "type": "result", "response": response })),
		Err(failure) => {
			emit(json!({ "type": "error", "name": failure.name, "message": failure.message }));
			std::process::exit(1);
		}
	}
	std::process::exit(0);
}
