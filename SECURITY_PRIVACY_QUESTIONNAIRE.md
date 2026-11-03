# Security & Privacy Questionnaire: Installed Web App Session Restore

This document provides answers to the [W3C TAG Security and Privacy Questionnaire](https://www.w3.org/TR/security-privacy-questionnaire/) for the [Installed Web App Session Restore Explainer](README.md).

### 2.1 What information might this feature expose to Web sites or other parties, and for what purposes is that exposure necessary?
In Track 1, `create({ restore })` exposes the new public key via `getPublicKey()`. After explicit user consent on a restored target device (Rule 5), `get({ restore })` exposes `authenticatorData`, `clientDataJSON`, `signature`, `userHandle`, and an optional `restoredPayload`. In Track 2, `Sec-Session-Migrate` exposes a signature over the new target hardware public key. The origin's backend verifies this assertion or ticket to issue a fresh session cookie or bind a new hardware-backed DBSC key.

### 2.2 Do features in your specification expose the minimum amount of information necessary to enable their intended uses?
Yes. Raw session cookies, `localStorage`, and hardware-bound private keys never leave the source device. Encrypted backup transfers only the origin-scoped restore or migration escrow key and bounded restore metadata. Track 1 transfers `userId`, `userName`, and an optional `2048`-byte `restorationPayload`, while Track 2 transfers `account_hint`.

### 2.3 How do the features in your specification deal with personal information, personally-identifiable information (PII), or information derived from them?
The feature does not collect new PII. Track 1 requires `userName`, and Track 2 requires `account_hint` when migration is enabled. The target restore UI displays this account identifier to the user (Rule 5). The user agent never exposes `userName`, `account_hint`, or restore keys to password manager UIs or autofill prompts (Rule 6).

### 2.4 How do the features in your specification deal with sensitive information?
Restore keys and migration escrow keys are sensitive authentication credentials. User agents or operating systems store them in encrypted backup vaults (such as lock-screen-protected cloud backup). Web content never reads private restore keys in plaintext.

### 2.5 Does data exposed by your specification carry related but distinct information that may not be obvious to users?
In Track 1, the `authenticatorData` Backup State (`BS`) flag indicates cloud versus local device transfer. Relying parties accept both states without learning device hardware identity.

### 2.6 Will the features in your specification introduce new state for an origin that persists across browsing sessions?
Yes, by design, to survive device replacement. Six mandatory rules prevent this state from acting as a tracking supercookie or zombie cookie:
* **Rule 1 (Write-Only on Source Device):** The browser blocks reading a restore key on the source device that created it.
* **Rule 2 (One-Time Silent Read per Device Restore):** On a target device, the browser allows at most one silent read per OS restore event. It then revokes local silent access on that device.
* **Rule 3 (Strict Fate-Sharing with Site Data & Logout):** Restore keys are browsing data partitioned by `(Browser Profile, StorageKey / Container ID, Manifest ID, rpId)`. Clearing site data, receiving `Clear-Site-Data`, receiving `Set-Login: logged-out`, or calling `navigator.credentials.preventSilentAccess()` purges the restore key from local storage and cloud backup.

### 2.7 What information from the underlying platform, e.g. configuration data, is exposed by this specification to an origin?
Track 1 exposes only standard WebAuthn authenticator flags (`UP=0`, `UV`, `BE=1`, `BS`). Track 2 exposes only standard DBSC key-binding headers.

### 2.8 Does this specification allow an origin to send data to the underlying platform?
Yes. In Track 1, an authenticated top-level origin sends `rpId`, `userId`, required `userName`, `challenge`, and `pubKeyCredParams` to the restore store. It may also send an optional `restorationPayload` capped at `2048` bytes. In Track 2, the server returns DBSC registration parameters (`session_identifier`, `refresh_url`, `migrate_allowed`, and required `account_hint` when migration is enabled) in the `/dbsc/register` JSON response.

### 2.9 Do features in your specification enable access to device sensors?
No.

### 2.10 Do features in your specification enable new script execution/loading mechanisms?
No.

### 2.11 Do features in your specification allow an origin to access other devices?
No. Origins cannot discover, enumerate, or communicate with other devices directly. Cross-device transfer happens solely through the operating system's or user agent's encrypted backup-and-restore channel. Explicit user consent during device setup or first launch gates this transfer (Rule 5).

### 2.12 Do features in your specification allow an origin some measure of control over a user agent's native UI?
Minimal control. Track 1 requires `userName`, and Track 2 requires `account_hint` when migration is enabled. The target restore UI shows this account identifier to the user (Rule 5). To prevent UI spoofing, the user agent length-limits and BiDi-sanitizes both strings as plain text alongside the verified app name and origin. Under Rule 6, restore keys never appear in password manager UIs or autofill prompts.

### 2.13 What temporary identifiers do the features in your specification create or expose to the web?
Track 1 creates a `rawId` and Track 2 creates a `session_identifier`. Both are scoped to `(Browser Profile, StorageKey / Container ID, Manifest ID, rpId)`. The key is write-only on the source device (Rule 1) and readable once per target device restore (Rule 2). Therefore, sites cannot track users across sessions.

### 2.14 How does this specification distinguish between behavior in first-party and third-party contexts?
The browser requires `Set-Login: logged-in` only for enrollment (`create({ restore })` and `Secure-Session-Registration`). Restored apps launch logged out on the target device. Therefore, the browser restricts restoration (`get({ restore })` and `Sec-Session-Migrate`) to top-level installed web app contexts with user restore consent (Rule 5). It blocks cross-origin iframes and third-party contexts.

### 2.15 How do the features in this specification work in the context of a browser’s Private Browsing or Incognito mode?
The browser strictly disables session restore in Private Browsing and Incognito mode. Ephemeral profiles do not enroll restore keys and do not receive restored credentials from device backups.

### 2.16 Does this specification have both "Security Considerations" and "Privacy Considerations" sections?
Yes. The [Core Explainer](README.md) covers both in "The Alignment Gate & Non-Goals" and "Security, Privacy & Abuse Mitigations". [Track 1](track1-restore-credential.md) and [Track 2](track2-dbsc-session-restore.md) also document rule enforcement and threat mitigations.

### 2.17 Do features in your specification enable origins to downgrade default security protections?
No. All exchanges require a Secure Context (HTTPS). Track 2 re-binds sessions to a fresh local hardware TPM key on the target device rather than exporting hardware-bound keys.

### 2.18 What happens when a document that uses your feature is kept alive in BFCache (instead of getting destroyed) after navigation, and potentially gets reused on future navigations back to the document?
In Track 1, the browser aborts or rejects any in-flight `navigator.credentials.create({ restore })` or `navigator.credentials.get({ restore })` promise if the document enters BFCache. When restored from BFCache, a page cannot replay a consumed one-time silent restore grant because Rule 2 revokes local silent access after the first read. BFCache does not affect Track 2 because Track 2 operates in the network stack during navigation.

### 2.19 What happens when a document that uses your feature gets disconnected?
If a document disconnects or destroys its browsing context during a Track 1 `create()` or `get()` call, the user agent aborts the operation. It then rejects the promise. In Track 2, the network stack consumes the target device's one-time restore grant the moment it transmits `Sec-Session-Migrate` on the wire. If navigation cancels before wire transmission, the browser preserves the grant.

### 2.20 Does your spec define when and how new kinds of errors should be raised?
Yes. In Track 1, `navigator.credentials.get({ restore, mediation: "silent" })` rejects with `NotAllowedError` with constant timing across all failure modes. It produces the same error whether the user declined app restore, no backup exists, or the browser already consumed the grant. Calling `get()` on a restored target device consumes the one-time silent grant even if `allowCredentials` fails to match. This prevents credential-ID probing.

### 2.21 Does your feature allow sites to learn about the user's use of assistive technology?
No.

### 2.22 What should this questionnaire have asked?
* **How does this feature interact with clearing browsing data vs. uninstalling an app?** Under Rule 3, restore keys are browser-partitioned browsing data. Clearing cookies or site data in the browser must purge the restore key, even if stored in an OS backup module. Otherwise, launching an installed web app wrapper could silently re-authenticate a logged-out user.
* **How does this feature prevent coercive install walls?** Rule 1 makes restore keys write-only on the source device. Rule 3 ties them to site data clearing. Therefore, sites cannot use them as undeletable device identifiers.
