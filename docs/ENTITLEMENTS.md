# Entitlement and Provisioning Requirements

Developer account in use: team Z3NP36C65D ("rohan bhadiyadra"),
UID 7RXM93A66V. One codesigning identity present (Apple Development). No
Developer ID Application cert yet.

## Query the current state yourself (read-only)

```
security find-identity -v -p codesigning
security cms -D -i <profile>.mobileprovision | plutil -p -
systemextensionsctl list
csrutil status
```

To check whether Apple has granted the ES entitlement: Developer account ->
Certificates, Identifiers & Profiles -> Identifiers -> (your App ID) ->
Additional Capabilities -> look for "Endpoint Security". If the tab or option
is absent, access is not granted. The request produces an auto-ACK email with
a 9-digit case number.

## Required items, in dependency order

1. Apple Developer Program membership (paid, USD 99/yr). Team Z3NP36C65D
   exists. **Status: paid 2026-10-08.** Confirm the account type (Individual vs
   Organization) in the portal; both can request ES but descriptions differ.

2. **Endpoint Security entitlement** `com.apple.developer.endpoint-security.client`.
   - Restricted, manual Apple approval. Two current request paths:
     (a) the form at https://developer.apple.com/contact/request/system-extension/ ,
     (b) the newer Capability Requests tab under
     Certificates, Identifiers & Profiles > Identifiers.
   - Describe the use case honestly (personal macOS EDR); text in
     `APPLE_ES_REQUEST.md`.
   - Gates component A (real sensor) and AUTH-based execution denial.
   - **This is the critical path item.** Local state 2026-10-08: not granted.

3. **System Extension install capability**
   `com.apple.developer.system-extension.install` on the host app bundle
   (standard, self-service in Xcode Capabilities).

4. **Provisioning profiles**
   - Host app: profile with System Extension capability.
   - Extension: profile with Endpoint Security capability (exists only after
     step 2 is granted).
   - Type: Mac App Development for local testing; Developer ID for
     distribution.
   - Manual signing is typical for restricted entitlements.

5. **Developer ID Application certificate** for signing/notarizing for
   distribution to other machines. **Not needed for M1/M2 local testing**: a
   Development provisioning profile signed with the existing Apple Development
   certificate is what local ES testing uses. Create the Developer ID cert at
   packaging time (M8).

6. **Full Disk Access (TCC)** for the responsible process (Terminal during
   eslogger work; the installed daemon/extension in production). This is a
   user-granted privacy approval, not an entitlement.

7. **Virtualization entitlement** `com.apple.security.virtualization`
   (self-service) for the sandbox app (M4).

8. **Network Extension capability**
   `com.apple.developer.networking.networkextension` with
   content-filter-provider (self-service) for network containment (M5). Adds a
   second system extension and another user-approval step.

## Current local state

- Identities: 1 (Apple Development only). No Developer ID.
- Provisioning profiles present: 1 (S&R project). None with ES capability.
- System extensions: Tailscale only. No Virux extension.
- Developer mode (`systemextensionsctl developer on`) is not usable while SIP
  is enabled on macOS 15+; the provisioning-profile path is required.

## Honesty constraints

- Do not bypass macOS security controls to test ES. Do not disable SIP.
- If the ES entitlement is not granted, mark component A blocked and rely on
  the eslogger bridge; do not fabricate sensor capability.
