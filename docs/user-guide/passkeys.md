# Passkeys

Passkeys are a modern, phishing-resistant replacement for passwords. One tap on your phone, one touch on a security key, or one prompt from your computer and you are signed in. No password, no 6-digit code, no email round-trip.

A passkey replaces both your password and your two-step verification code in a single step. It is not "just another 2FA option"; it is a complete sign-in method on its own.

## How passkeys work

Passkeys use public-key cryptography. When you register a passkey, two keys are generated:

- A **private key** that stays on your device (phone, laptop, or security key).
- A **public key** that is sent to WeftID and stored against your account.

When you sign in, the device proves it holds the private key by signing a fresh challenge from WeftID. WeftID verifies the signature with the public key. The private key is never transmitted and never leaves the device.

### Why the PIN or fingerprint is safe

A common worry is that a 4- or 6-digit PIN looks trivial to brute-force. With passkeys, the PIN never has to stand up to that kind of attack, for three reasons:

1. **The PIN stays on the device.** It unlocks a local keystore (your phone's Secure Enclave, your laptop's TPM, your YubiKey's secure element). It is never sent to WeftID or to any website.
2. **The hardware rate-limits attempts.** After a small number of wrong PINs (typically 5 to 10) the device locks or wipes the key material. An attacker cannot run millions of guesses per second the way they can against a leaked password hash.
3. **The attacker needs the device, too.** Knowing your PIN is useless without physical access to the device that holds the private key. This is why a passkey is "two factors" at once: something you have (the device) plus something you know or are (the PIN or biometric).

### Why passkeys resist phishing

A password can be handed to any website that asks convincingly. A passkey cannot. The browser only releases a signed assertion to the exact domain (the "relying party ID") that the passkey was registered against. If you are tricked into visiting a look-alike domain, your device will simply refuse to produce a signature. There is nothing to type, nothing to paste, and nothing to leak.

### Synced passkeys and your credential manager

iCloud Keychain, Google Password Manager, and Microsoft account sync all back up passkeys to the cloud so they roam across your devices. This is convenient but shifts part of the trust to your credential-manager account. If an attacker takes over your Apple ID, Google account, or Microsoft account, they can reach your synced passkeys.

Keep your credential-manager account protected with its own strong 2FA.

## Credential managers at a glance

WeftID works with any WebAuthn-compliant authenticator. The most common ones:

- **iCloud Keychain** (Apple devices, Safari, Chrome on macOS/iOS). Passkeys sync across all devices signed in to the same Apple ID. Prompts say "Sign in with your passkey" and show an Apple-style sheet.
- **Google Password Manager** (Chrome on Android, ChromeOS, desktop Chrome signed in to a Google account). Syncs across Chrome on all your devices. Prompts show the Google Password Manager dialog.
- **Windows Hello** (Windows 10/11). Backed by the machine's TPM. Not synced: a Windows Hello passkey lives on that one PC. Prompt is the Windows security dialog (PIN, fingerprint, or camera).
- **Hardware security keys** (YubiKey, Google Titan, SoloKeys). Physical USB or NFC devices. Not synced: the passkey lives on the key itself. You tap the key when prompted.
- **Third-party credential managers** (1Password, Dashlane, Bitwarden, and others) increasingly support passkeys as well and sync through their own apps.

When you register a passkey the browser decides which credential manager captures it, based on what is available on the device. If you would prefer a different one (for example, a YubiKey instead of iCloud Keychain), cancel the prompt and pick the alternative from the browser's "Use another device" option.

### Naming guidance

Name passkeys by the credential manager type, not the specific device:

- **Good:** "iCloud Keychain", "Google Password Manager", "YubiKey 5", "Windows Hello on my work laptop"
- **Not great:** "iPhone 15 Pro" (the passkey roams to your iPad and Mac too)

A passkey in iCloud Keychain is the same passkey on every device signed in to that Apple ID. Naming it after one device gets misleading fast.

## Registering a passkey

1. Go to **Account > Two-Step Verification**.
2. Under **Passkeys**, click **Register a new passkey**.
3. Follow your browser's prompt. Touch your security key, scan your fingerprint, or enter your device PIN.
4. Give the passkey a name (see guidance above).
5. If this is your first passkey, save the backup codes shown. They are the last-resort recovery path if you lose every device.

## Recovery strategy: register two passkeys

A single passkey on a single device is a single point of failure. Lose the device, lose the sign-in.

The recommended setup is to register at least two passkeys on different credential managers. For example:

- **iCloud Keychain** plus a **YubiKey** you keep in a drawer.
- **Google Password Manager** plus **Windows Hello** on your work PC.
- **1Password** plus a **hardware security key**.

If one fails, the other still signs you in. Backup codes exist as a final fallback but require you to store them somewhere safe outside WeftID.

## Signing in with a passkey

1. Enter your email on the sign-in page.
2. Your browser pops up the passkey prompt. Approve with your PIN, fingerprint, or key tap.
3. You land on the dashboard. That is the entire flow.

If the passkey prompt is dismissed, cancelled, or fails, WeftID falls back to the normal password and two-step verification flow. Nothing is broken; you can try the passkey again or fall back to your password.

## Revoking a passkey

On the **Account > Two-Step Verification** page, each registered passkey has a **Revoke** button. Revoking a passkey immediately removes its public key from WeftID. The private key on the device becomes a dead credential; it can no longer sign in.

Admins can also revoke a user's passkey from the user detail page under **Users > (user) > Profile**. Revoking a compromised device is the right first step if a laptop or phone is lost.
