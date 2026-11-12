//! Runs one WebAuthn passkey ceremony with the user's phone, over the FIDO hybrid transport: the
//! caller shows a QR code, the phone scans it and proves it is nearby over Bluetooth, and the
//! ceremony runs through an encrypted tunnel. Apps whose web view has no passkey prompt, such as
//! Electron on Linux, start this helper for each ceremony (the Amp Linux app does).
//!
//! Protocol: one JSON line on stdin, `{"ceremony":"get"|"create","origin":"https://…",
//! "options":{…}}`, with the server's options as `@simplewebauthn/browser` takes them. Then JSON
//! lines on stdout: `{"type":"qr","url":"FIDO:/…","svg":"<svg…>"}`, any number of
//! `{"type":"status","status":…}`, and last either `{"type":"result","response":{…}}` with the
//! credential JSON, or `{"type":"error","name":…,"message":…}` with the DOM exception name a
//! browser would throw. A `NotSupportedError` for Bluetooth adds `"reason"`: `bluetooth-off`
//! when the adapter is powered off, or `bluetooth-unavailable` when there is none. The app
//! cancels a ceremony by killing the process.
//!
//! The caller owns the origin check: this helper signs for whatever origin it is given, as a
//! browser does for its own pages. Any local process could already reach the phone over
//! Bluetooth itself, so the helper grants nothing new.
//!
//! `amp-passkey-helper --version` prints `{"name":…,"version":…,"protocol":1}`, so a caller can
//! refuse a helper whose protocol it does not speak.
//!
//! `amp-passkey-helper --demo` signs a random challenge for https://ampcode.com and prints the QR
//! code to the terminal, to try the Bluetooth and tunnel part without the app.

use std::io::{BufRead, Read};

use btleplug::api::{Central as _, CentralState, Manager as _};
use btleplug::platform::Manager;

use libwebauthn::UvUpdate;
use libwebauthn::ops::webauthn::{
	GetAssertionRequest, JsonFormat, MakeCredentialRequest, OriginValidation, RequestOrigin,
	RequestSettings, WebAuthnIDLResponse as _,
};
use libwebauthn::proto::CtapError;
use libwebauthn::transport::hybrid::channel::{HybridUxUpdate, PxpUpdate};
use libwebauthn::transport::hybrid::qr_code_device::{
	PxpQrCodeDevice, PxpTransports, QrCodeOperationHint,
};
use libwebauthn::transport::{Channel as _, ChannelSettings, Device as _};
use libwebauthn::webauthn::{WebAuthn as _, WebAuthnError};
use serde_json::{Value, json};

/// The version of the stdin and stdout protocol in the module documentation. Raise it when a change
/// would break a caller written for the previous version; `--version` reports it.
const PROTOCOL_VERSION: u32 = 1;

struct Request {
	create: bool,
	origin: String,
	options: Value,
}

/// A failure, as the DOM exception a browser would reject `navigator.credentials` with.
struct Failure {
	name: &'static str,
	message: String,
	/// Why the ceremony could not start, for a caller that explains it: `bluetooth-off` or
	/// `bluetooth-unavailable`.
	reason: Option<&'static str>,
}

impl Failure {
	fn new(name: &'static str, message: impl Into<String>) -> Self {
		Self {
			name,
			message: message.into(),
			reason: None,
		}
	}

	fn bluetooth(reason: &'static str, message: &str) -> Self {
		Self {
			reason: Some(reason),
			..Self::new("NotSupportedError", message)
		}
	}
}

/// Fails unless a Bluetooth adapter is powered on. libwebauthn checks only that one exists, and
/// with it powered off the phone's proximity check waits until the caller gives up.
async fn require_bluetooth() -> Result<(), Failure> {
	let unavailable = || {
		Failure::bluetooth(
			"bluetooth-unavailable",
			"No Bluetooth adapter is available. Signing in with a phone needs Bluetooth.",
		)
	};
	let manager = Manager::new().await.map_err(|_| unavailable())?;
	let adapters = manager.adapters().await.map_err(|_| unavailable())?;
	if adapters.is_empty() {
		return Err(unavailable());
	}
	for adapter in adapters {
		if matches!(adapter.adapter_state().await, Ok(CentralState::PoweredOn)) {
			return Ok(());
		}
	}
	Err(Failure::bluetooth(
		"bluetooth-off",
		"Bluetooth is turned off. Signing in with a phone needs Bluetooth.",
	))
}

fn emit(event: Value) {
	println!("{event}");
}

fn read_request() -> Result<Request, Failure> {
	let mut line = String::new();
	std::io::stdin()
		.lock()
		.read_line(&mut line)
		.map_err(|error| {
			Failure::new("TypeError", format!("Could not read the request: {error}"))
		})?;
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

fn failure_for_ceremony(error: WebAuthnError<impl std::fmt::Display>, create: bool) -> Failure {
	match error {
		WebAuthnError::Ctap(CtapError::CredentialExcluded) if create => Failure::new(
			"InvalidStateError",
			"This phone already has a passkey for this account",
		),
		WebAuthnError::Ctap(CtapError::NoCredentials) => Failure::new(
			"NotAllowedError",
			"This phone has no passkey for this account",
		),
		error => Failure::new("NotAllowedError", error.to_string()),
	}
}

async fn run(request: Request, demo: bool) -> Result<Value, Failure> {
	require_bluetooth().await?;
	let origin: RequestOrigin = request
		.origin
		.as_str()
		.try_into()
		.map_err(|_| Failure::new("SecurityError", "Invalid origin"))?;
	let settings = RequestSettings {
		origin: OriginValidation::Trust,
	};
	let options = request.options.to_string();
	let hint = if request.create {
		QrCodeOperationHint::MakeCredential
	} else {
		QrCodeOperationHint::GetAssertionRequest
	};
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
			"{image}\nScan this with your phone's camera. Keep the phone near this computer."
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

	let response = if request.create {
		let request = MakeCredentialRequest::prepare(&origin, &options, &settings)
			.await
			.map_err(|error| Failure::new("TypeError", error.to_string()))?;
		let response = channel
			.webauthn_make_credential(&request)
			.await
			.map_err(|error| failure_for_ceremony(error, true))?;
		response.to_json_string(&request, JsonFormat::Minified)
	} else {
		let request = GetAssertionRequest::prepare(&origin, &options, &settings)
			.await
			.map_err(|error| Failure::new("TypeError", error.to_string()))?;
		let response = channel
			.webauthn_get_assertion(&request)
			.await
			.map_err(|error| failure_for_ceremony(error, false))?;
		// The phone lets the user pick one passkey, so it returns one assertion.
		let assertion = response
			.assertions
			.first()
			.ok_or_else(|| Failure::new("NotAllowedError", "The phone returned no passkey"))?;
		assertion.to_json_string(&request, JsonFormat::Minified)
	};
	channel.close().await;
	let response = response.map_err(|error| Failure::new("NotAllowedError", error.to_string()))?;
	serde_json::from_str(&response)
		.map_err(|error| Failure::new("NotAllowedError", error.to_string()))
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
	let result = match if demo {
		Ok(demo_request())
	} else {
		read_request()
	} {
		Ok(request) => run(request, demo).await,
		Err(failure) => Err(failure),
	};
	match result {
		Ok(response) => emit(json!({ "type": "result", "response": response })),
		Err(failure) => {
			let mut event =
				json!({ "type": "error", "name": failure.name, "message": failure.message });
			if let Some(reason) = failure.reason {
				event["reason"] = json!(reason);
			}
			emit(event);
			std::process::exit(1);
		}
	}
}
