# RDPSVC.R4X

`RDPSVC.R4X` is an independent R4OS service implemented in Zig.

## Package

- Version: `0.1.10`
- Image target: `/R4OS/SERVICES/RDPSVC.R4X`
- Image scope: `full`
- Canonical project manifest: `module.R4MF`

The manifest is the single source of truth for the artifact, imports, image
target, and package metadata.

## Build

On Windows:

    Build.bat

On Linux or macOS:

    ./Build.sh

The build starters resolve the current local R4OS dependency checkouts through
`Settings.R4S`. The URL and hash entries in `build.zig.zon` record the
last verified standalone dependency identities; workspace builds use the
mapped local checkouts.

## Documentation

Detailed German technical notes from the migration are preserved in
`DOCUMENTATION.de.txt`. Source-transfer provenance is recorded in
`PROVENANCE.txt`.

The productive bitmap path advertises exactly NSCodec, selects it only when
the negotiated client capabilities and measured wire size justify it, and
otherwise retains the RLE16/Raw fallback. Stable recurring tiles can be
published through the negotiated Revision 3 bitmap cache and reused by
MemBlt after generation validation.

## License

Original R4OS material is licensed under Apache License 2.0. See `LICENSE`
and `NOTICE`. Any repository-specific external material is documented in
`THIRD_PARTY_NOTICES.md`.


RDPSVC: Anmeldebesitz ab 0.78.62
------------------------------
RDPSVC 0.1.8 liest UserName/Password aus SYSTEM\Services\RDPSVC beim Start.
Die Startvorpruefung validiert nur Konfiguration und Modulvertraege; sie
fuehrt keine synthetischen Anmeldungen aus und zaehlt keine Auth-Erfolge.
Nach dem TLS-Handshake liefert R4TLS-Op33 den gebundenen SubjectPublicKey.
R4AUTH-Op21 eroeffnet daraufhin den opaken Zustand; drei Op19-Schritte
uebernehmen Type1, Type3 plus pubKeyAuth und abschliessend authInfo.
Private Zustands-/Eingabepuffer bleiben beim Dienst und werden beim
Verlassen geleert. Nur die getrennte Netzwerkantwort wird TLS-verschluesselt
versandt. Der Dienst implementiert keine eigene ASN.1-/NTLM-Kryptografie.

Erst nach vollstaendiger Pruefung zaehlt der Dienst die Anmeldung und
meldet den gebundenen konfigurierten Benutzer. Die spaetere RDP-Aktivierung
darf keinen anderen Benutzer einsetzen. Im reinen TLS-Modus ohne CredSSP
prueft die Aktivierung selbst Benutzer und Kennwort. Fehlerberichte verwenden
dieselbe konfigurierte Identitaet. Die bestehenden LogPasswords-Einstellungen
bleiben wirksam; der lokale Test setzt LogPasswords=false.

Version 0.1.10 emits NSCodec planes in bottom-up wire order while the
capture input and local decoder remain top-down. A synchronization-only
input PDU is accepted without creating a desktop event or reporting an error.
The existing codec checks include an asymmetric literal-plane fixture.
Reference: [FreeRDP 3.15.0 NSCodec encoder](https://github.com/FreeRDP/FreeRDP/blob/3.15.0/libfreerdp/codec/nsc_encode.c).
