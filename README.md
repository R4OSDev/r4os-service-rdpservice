# RDPSVC.R4X

`RDPSVC.R4X` is an independent R4OS service implemented in Zig.

## Package

- Version: `0.1.7`
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


Sitzungsbesitz ab 0.78.61
-----------------------
RDPSVC erzeugt vor der CredSSP-Schleife per R4AUTH-Op21 eine verbindungseigene
Challenge, uebergibt sie an Op12 und in jedem R4C2-Frame an Op19 und loescht
sie beim Verlassen der Schleife. Andere Verbindungen teilen diesen Zustand
nicht. Die TLS-Handshakes verwenden R4L2; seine privaten Begin-/Finish-Puffer
werden nach Abschluss oder Fehler geleert. Nur die getrennte Flight wird
versandt. Phasen-/Kennwort- und vollstaendige Bindungspruefung folgen in62.
