const Pi = window.Pi;
const apiBase = window.location.protocol === "file:" ? "http://localhost:31415" : window.location.origin;
let latestAuth = null;
let latestDeviceFingerprint = null;
let latestMfaChallenge = null;
 
const output = document.getElementById("output");
const piStatus = document.getElementById("pi-status");
const loginButton = document.getElementById("pi-login");
const rotationForm = document.getElementById("rotation-form");
 
function writeOutput(label, payload) {
    output.textContent = `${label}\n${JSON.stringify(payload, null, 2)}`;
}
 

function onIncompletePaymentFound(payment) {
    console.log("Incomplete Pi payment found", payment);
}
 
if (Pi) {
    Pi.init({
        version: "2.0",
        sandbox: true
    });
    piStatus.textContent = "Pi Browser detected. Sandbox SDK initialized.";
    console.log("Pi Browser detected");
} else {
    piStatus.textContent = "Pi Browser not detected. Open this app in Pi Browser for real Pi authentication.";
    console.warn("Please open in Pi Browser");
}
 
async function authenticateUser() {
    if (!Pi) {
        writeOutput("Pi SDK unavailable", {
            message: "Please open in Pi Browser. Demo mode can still exercise backend passphrase rotation."
        });
        return null;
    }
 
    try {
        const scopes = ["username", "payments"];
        latestAuth = await Pi.authenticate(scopes, onIncompletePaymentFound);
        document.getElementById("username").value = latestAuth?.user?.username || "pi_sandbox_user";
        writeOutput("Pi authentication complete", latestAuth);
        return latestAuth;
     } catch (err) {

        console.error(err);
        writeOutput("Pi authentication failed", { error: err.message || String(err) });
        return null;
     }
 }

async function postJson(path, body) {
    const response = await fetch(`${apiBase}${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
    });
    const payload = await response.json();
    if (!response.ok) {
        throw new Error(payload.error || `Request failed with ${response.status}`);
    }
    return payload;
}

async function prepareSecurityContext(username) {
    const piAuthUid = latestAuth?.user?.uid || null;
    latestMfaChallenge = await postJson("/api/mfa/challenge", {
        username,
        pi_auth_uid: piAuthUid
    });
    const fingerprint = await postJson("/api/wallet/fingerprint", { username });
    latestDeviceFingerprint = fingerprint.device_fingerprint;
    return {
        mfa_challenge: latestMfaChallenge,
        device_fingerprint: latestDeviceFingerprint
    };
 }

async function rotatePassphrase(event) {
    event.preventDefault();
 

    const username = document.getElementById("username").value.trim();
    const biometricCheckbox = document.getElementById("biometric-confirmed");

    if (!username) {
        writeOutput("Validation blocked", { error: "Username is required." });
        return;
    }

    if (!biometricCheckbox.checked) {
        writeOutput("Validation blocked", {
            error: "Please confirm biometric authentication before rotating your passphrase."
        });
        return;
    }

    const context = await prepareSecurityContext(username);
    const piAuthUid = latestAuth?.user?.uid || null;
    const body = {
        username,
        current_passphrase: document.getElementById("current-passphrase").value,
        new_passphrase: document.getElementById("new-passphrase").value,
        biometric_confirmed: biometricCheckbox.checked,
        device_fingerprint: context.device_fingerprint,
        mfa_challenge_id: context.mfa_challenge.challenge_id
    };
    if (piAuthUid) {
        body.pi_auth_uid = piAuthUid;
    }

    try {
        const rotation = await postJson("/api/wallet/rotate-passphrase", body);
        const dashboard = await fetch(`${apiBase}/api/security/dashboard`).then((res) => res.json());
        writeOutput("Passphrase rotated", { rotation, dashboard });
        rotationForm.reset();
        document.getElementById("username").value = username;
    } catch (err) {
        writeOutput("Rotation blocked", {
            error: err.message,
            context
        });
    }
 }

loginButton.addEventListener("click", authenticateUser);
rotationForm.addEventListener("submit", rotatePassphrase);
window.authenticateUser = authenticateUser;
