# Requesting the Endpoint Security Entitlement from Apple

This is the critical path for the real sensor (M2). It cannot be automated;
it needs a human signed into the Apple Developer account. This page gives the
exact steps and ready-to-paste text.

## Account type: Individual (important)

This team is an **Individual** membership. Public guidance (The Art of Mac
Malware, and older Apple forum threads) notes Apple has historically preferred
organization accounts for this entitlement, and the request form asks for a
company. Individuals do apply and the situation appears to have loosened since
~2022, but a decline is a real possibility. Keep expectations honest.

If declined, the escalation paths are:
- Re-apply with a sharper, evidence-based justification (the wording below),
  and reference the case number.
- Ask Apple, via the case, what additional detail would qualify a personal
  research project.
- Upgrade the membership to **Organization** (requires a legal entity and a
  **D-U-N-S number**), which is the path the books recommend.

Do NOT disable SIP as a workaround. It is forbidden by the project principles
(and by the safety rules for this machine).

## Where to go

Request form: https://developer.apple.com/contact/request/system-extension/
(Apple Developer > Account > Resources, or the "Request a System Extension or
DriverKit Entitlement" form.)

You must be signed in with the account that owns team **Z3NP36C65D**
("rohan bhadiyadra"). A paid Developer Program membership is required.

## Steps

1. Open the form URL, sign in as team Z3NP36C65D.
2. Select the entitlement: **Endpoint Security client**
   (`com.apple.developer.endpoint-security.client`).
3. Fill in developer/company details (the account already carries the name).
4. Paste the description below, adjusted if you want to name the product
   explicitly. Apple wants the use case, the platforms, and how the
   entitlement is used.
5. Submit. You get an auto-ACK email with a 9-digit case number starting with
   7. Save it.
6. Approval is manual; lead times range from days to about a month.
7. When granted, create an App ID and an Additional Capability "Endpoint
   Security", then a provisioning profile carrying it. See
   `docs/ENTITLEMENTS.md`.

## Ready-to-paste description (Individual account)

> I am an individual developer, and a graduate student in cybersecurity. I am
> building a personal, local-first Endpoint Detection and Response (EDR) tool
> for macOS on Apple silicon, for use on my own Mac and for my own research
> and study. It is a non-commercial personal project: it does not run as a
> service for other people, and it does not upload user files or samples to any
> external service.
>
> I need the Endpoint Security client entitlement to subscribe to NOTIFY events
> (process exec/fork/exit, file open/close, mount, signal, and the code-signing
> identity carried in the event stream) so I can build an explainable,
> evidence-based local detection pipeline. My goal is to detect suspicious
> process ancestry, unexpected persistence (launch agents, launch daemons, and
> login items), suspicious file activity, and ransomware-style mass encryption
> or renaming patterns, and to present each finding to the user with the
> supporting evidence.
>
> The tool begins in observe-only mode. Any containment, or AUTH-based
> execution denial, will come later and only after I have measured a
> false-positive baseline on my own machine, with administrator authentication
> for sensitive actions. Telemetry is stored locally in a compact SQLite
> database with a configurable retention window.
>
> The tool does not disable SIP, Gatekeeper, or XProtect, and it does not
> bypass any macOS security control. The containing app is a Swift system
> extension installed via the System Extensions framework, on my own
> Apple-silicon Mac. I would also like to test locally using a development
> provisioning profile before any wider use.

Adjust the student line to match your institution if you prefer; it is genuine
and it strengthens the case. Keep the precise technical detail; Apple responds
to specificity.

## After approval: local verification

```
# Should list an "Apple Development" or "Developer ID Application" identity:
security find-identity -v -p codesigning

# After creating the App ID + profile, import it and confirm:
# Developer > Account > Certificates, Identifiers & Profiles > Identifiers
#   -> your App ID -> Additional Capabilities -> "Endpoint Security" present
```

Then M2 can replace the eslogger bridge (`EsloggerAdapter`) with a real
`ESSensor` implementing the same `EventSource` protocol, with no change to the
store, CLI, or UI.