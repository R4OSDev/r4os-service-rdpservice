RDPSVC.R4X
==========

RDPSVC.R4X ist der RDP-Serverdienst fuer R4OS.

Stand 0.59.6:

- Service-Name: `RDPSVC`
- Zielpfad im Image: `C:\R4OS\SERVICES\RDPSVC.R4X`
- Standard-Port im Gast: `3389`
- QEMU-Standardweiterleitung: Host `127.0.0.1:13389` -> R4OS `10.0.2.15:3389`
- Registry-Pfad: `SYSTEM\Services\RDPSVC`
- Standard-Zugangsdaten: `r4os` / `rosebud`
- Standard-Service-Start: `auto`

0.52.11 legt die dauerhafte Dienst- und Netzbasis an. Der Dienst registriert
einen normalen Service-Endpunkt, schreibt Registry-Defaults, lauscht ueber
`TCPSVC` auf Port 3389 und nutzt fuer den Listener den nicht-blockierenden
TCP-Servicepfad `ACCEPT_POLL`, damit der Service-Endpunkt waehrend des
Wartens auf eingehende Verbindungen erreichbar bleibt.

Seit 0.52.12 spricht RDPSVC die erste echte RDP-Transportkante: TPKT,
X.224 Connection Request/Confirm und RDP Negotiation Request/Response.

Seit 0.52.13 fuehrt der Dienst die klassische RDP-Aktivierung bis zur aktiven
Session aus: MCS Connect Initial/Response, Erect Domain, Attach User, Channel
Join, Client Info, Demand Active, Confirm Active, Synchronize, Control, Font
List und Font Map. RDPSVC waehlt klassisches RDP (`selectedProtocol=0`) und
meldet im GCC-Security-Block bewusst `ENCRYPTION_METHOD_NONE` und
`ENCRYPTION_LEVEL_NONE`; TLS, CredSSP und NLA werden nicht als halbe Fallbacks
simuliert. Die Anmeldung nutzt `r4os:rosebud` aus der Registry, loggt
Auth-Versuche diagnostisch und fuehrt weiterhin kein R4OS-User- oder
Rechtemodell ein.

`SERVMAN STATUS RDPSVC` zeigt Transport-, MCS-, Security-, Client-Info-,
Auth-, Activation-, Sync-/Control-, Font- und Client-Core-Groessenzaehler.
Seit 0.52.15 nutzt RDPSVC den oeffentlichen R4DESK-Remote-Frame-Vertrag und
sendet nach Font Map erste unkomprimierte RDP-Bitmap-Updates aus dem XRGB32-
Desktop-Snapshot. Seit 0.52.16 mappt RDPSVC RDP-Input-PDUs fuer Tastatur,
Mausbewegung, Buttons und Wheel auf den oeffentlichen R4DESK-Remote-Input-
Vertrag. Der Dienst liest keine Desktop-Interna, keinen Kernel-Framebuffer,
keinen WINSVC-Pixelpfad und injiziert keine Treiber-/IRQ-Eingaben. Desktop
entscheidet weiterhin Fokus, Capture und Zustellung. `SERVMAN STATUS RDPSVC`
zeigt zusaetzlich Bitmap-/Frame-Zaehler, Dirty-Rect, letzte Revision,
Payload-Pruefsumme sowie Input-PDU-, Event-, Key-, Mouse-, Wheel- und
Push-Zaehler.

Seit 0.52.17 zaehlt RDPSVC den Session-Lifecycle explizit: abgeschlossene
Sitzungen, Reconnects, erkannte Disconnects, Cleanup, Close-Fehler,
Listener-Close, Session-Limit-Wartefaelle, letztes Session-Ergebnis und
letzter TCP-Disconnect-State. Nach erfolgreichem Remote-Input wartet der
Dienst kurz auf den Client-Disconnect und liest dafuer den bestehenden
`R4NET.tcpConnection`-Detailpfad. Service-Stop und Fehlerpfade schliessen den
Listener ueber `tcpCloseListenServiceResult`.

Seit 0.53.16 nutzt der RDPSVC-Service-Endpoint den queue-basierten
R4SYS-Vertrag mit Completion-Wait und ServiceInfo-Queue-Zaehlern. RDP-
Reconnects, Session-Limits, Lifecycle-Cleanup und echte RDP-Worker bleiben
weiterhin Dienstlogik; der Kernel-Service-Core bleibt bei Endpoint-Queue,
Wait und Diagnose.

Seit 0.53.21 ist die neue R4NET-Socket-Completion ein Client-/SDK-Vertrag
ueber `TCPSVC`; RDPSVC bleibt bei `ACCEPT_POLL` und eigener Session-Policy,
statt RDP-Transport oder Reconnect-Regeln in den Kernel zu verschieben.

Seit 0.55.14 erfasst RDPSVC die vom Client angeforderten RDP-Negotiation-
Protokolle explizit. `SERVMAN STATUS RDPSVC` zeigt `tls_req`, `nla_req`,
`rdstls_req`, `hybex_req`, `modern_req`, `classic_sel`, `classic_only`,
`compat_mask` und `compat_blocker`.

Seit 0.55.16 wird der moderne mstsc-Pfad als wiederverwendbare
Security-Protocol-Linie gefuehrt. `R4TLS.R4P` besitzt die Rolle
`security.tls`, `R4AUTH.R4P` die Rolle `security.credssp` mit Dependency auf
`security.tls`. RDPSVC bleibt RDP-Konsument: TLS-Record-/Handshake-,
CredSSP-/SPNEGO-/NTLM- und Zertifikatslogik gehoeren nicht in diesen Dienst,
sondern in die R4P-Protokollschicht, damit spaeter auch andere Anwendungen
diese Basis nutzen koennen.

Seit 0.55.21 waehlt RDPSVC bei modernen Angeboten nicht mehr still Classic.
`SSL`, `HYBRID` und `HYBRID_EX` werden im X.224-Confirm als gewaehltes
Security-Protokoll bestaetigt und danach ueber R4TLS/R4AUTH-Kontrakte
gefuehrt. `SERVMAN STATUS RDPSVC` zeigt zusaetzlich `sec_state`,
`sec_classic`, `sec_tls`, `sec_credssp`, `sec_auth_ok`, `sec_auth_fail`,
`tls_alert`, `r4tls` und `r4auth`. `RDSTLS` bleibt ein expliziter Blocker
(`rdstls-not-supported`).

Seit 0.55.29 prueft RDPSVC beim Service-Start die R4TLS-Session-Vertraege
`op20/op21` und die R4AUTH-Windows-CredSSP-Vertraege `op15/op17` als
ModernSecurityProfile vor und gibt dieses Profil an die Session-Worker weiter.
Bei erfolgreichem Contract-/Harness-Pfad zaehlt der Dienst `tls_session`,
`credssp_windows` und `modern_active`, setzt `sec_state` auf `modern_active`
und sendet keinen erwarteten R4TLS-Alert mehr. Interne Modern-Readiness-
Blocker bleiben Status-/Blocker-Daten; R4TLS-Alerts sind fuer echte TLS-Wire-
Fehler reserviert. TLS-/CredSSP-/NTLM-/ASN.1-Logik bleibt in R4TLS/R4AUTH und
wird nicht privat in RDPSVC dupliziert.

Nuetzliche Aufrufe:

    SERVMAN STATUS RDPSVC

Host-Abnahme:

    Tests/Runtime/Run-RdpServiceLiveTest.ps1

Der Host-Test baut ein Testimage mit normaler Desktop-Shell, aktiviert die
RDP-Sitzung ueber `127.0.0.1:13389`, validiert die empfangenen Bitmap-PDUs
bytegenau und sendet danach eine deterministische Eingabesequenz mit
Mausbewegung, Klick, Wheel und Unicode-Taste. Seit 0.52.17 fuehrt der Test
diese Aktivierung zweimal nacheinander aus und prueft danach einen kaputten
TPKT-Fehlerpfad. Erwartet werden initiales Bitmap, Input-Bitmap,
Reconnect-Bitmap und Reconnect-Input-Bitmap mit gueltiger Geometrie und
Pruefsummen. Seit 0.55.22 prueft der Wire-Harness zusaetzlich, dass eine
mstsc-nahe Negotiation-Probe mit `SSL|HYBRID|HYBRID_EX` nicht mehr auf
Classic umgebogen wird, sondern `HYBRID_EX` selektiert. Seit 0.55.29 erwartet
dieser Probe-Happy-Path keinen R4TLS-Alert mehr; stattdessen muss RDPSVC die
Modern-Activation-Vertraege ueber R4TLS/R4AUTH erfolgreich konsumieren.
Seit 0.55.27 besitzt R4TLS den Session-Harness fuer ClientKeyExchange,
ChangeCipherSpec, Client-Finished, Server-Finished und Sequenzen. RDPSVC
nutzt diese Logik seit 0.55.29 als Protocol-Vertrag und baut sie nicht
privat nach.
Seit 0.55.28 besitzt R4AUTH die Windows-nahe CredSSP/PubKeyAuth-Kante ueber
`R4CW`-Frames mit TLS-Public-Key-Hash. RDPSVC baut auch diese Logik nicht
privat nach; seit 0.55.29 konsumiert der Dienst den Windows-Harness als
Vorstufe zur finalen mstsc-End-to-End-Abnahme.
Seit 0.55.29 ist diese RDPSVC-Unterversion umgesetzt: R4TLS-Session-Harness
und R4AUTH-Windows-Harness werden vom Dienst als Protocol-Consumer genutzt.
Der Service preflightet diese Vertraege als ModernSecurityProfile, bevor
Session-Worker Clients annehmen.
Seit 0.55.30 besitzt R4TLS die Live-Session-API `op22`/`op23` mit
`R4LB`/`R4LS` und `R4LF`/`R4LK`. RDPSVC baut diese TLS-Sessionlogik weiter
nicht privat nach; die naechste RDPSVC-Arbeit ist ein Streamadapter, der
verschluesselte R4TLS-Application-Records konsumiert und danach R4AUTH-
CredSSP sowie RDP-Aktivierung ueber diesen geschuetzten Stream fuehrt.
Seit 0.55.31 besitzt R4AUTH dafuer den Live-CredSSP-Vertrag `op18`/`op19`/
`op20` ueber `R4CL` mit eingebettetem `R4LK`. RDPSVC bleibt in dieser
Unterversion bewusst unveraendert und konsumiert diesen Live-State erst in den
Folgeschritten.
Seit 0.55.32 ist der RDPSVC-R4TLS-Streamadapter als Preflight-Vertrag
angeschlossen. Der Dienst prueft R4TLS `op22`/`op23`, den Produktivvertrag
fuer `op24`/`op25` und den R4TLS-Selftest mit `live=ok`, `app_write=ok` und
`app_read=ok`. `SERVMAN STATUS RDPSVC` zeigt zusaetzlich `tls_live` und
`tls_stream`. RDPSVC interpretiert `R4LK` nicht selbst und enthaelt weiter
keine AES-, HMAC-, X25519-, TLS-Parser- oder CredSSP-Privatlogik.
Seit 0.55.33 konsumiert RDPSVC den R4AUTH-Live-CredSSP-Vertrag `op18`/`op20`
als Teil seines ModernSecurityProfile. Der Dienst prueft dabei die festen
R4OS-Zugangsdaten `r4os`/`rosebud`, die R4LK-Public-Key-Bindung und die
negativen Fehlerpfade fuer falsches Passwort, Kerberos, Domain, kaputte
TSRequest und fehlenden TLS-Kontext. `SERVMAN STATUS RDPSVC` zeigt dafuer
`credssp_live` und `credssp_loop`; RDPSVC bleibt trotzdem nur Consumer und
fuehrt keine eigene R4CL-, R4LK-, SPNEGO-, NTLM- oder Kryptografie-Logik.
Seit 0.55.34 fuehrt RDPSVC nach dem ModernSecurityProfile die normale
RDP-Aktivierung ueber einen expliziten `modern_protected`-Aktivierungsmodus
weiter. `modern_active` wird dadurch erst nach MCS, Client Info, Demand/Confirm
Active, Bitmap und Input gesetzt; der reine TLS/CredSSP-Preflight meldet nur
noch `modern-security-ok`. `SERVMAN STATUS RDPSVC` zeigt zusaetzlich
`modern_stream`. Der Host-Harness prueft eine Modern-Aktivierung mit
`HYBRID_EX`, Bitmap und Input; echte Windows-`mstsc.exe`-End-to-End-Abnahme
bleibt die folgende Unterversion.
Seit 0.55.35 ist diese folgende Unterversion als mstsc-Gate-Audit gefuehrt:
Der `HYBRID_EX`-Harness ist kein echter Windows-mstsc-Erfolg, solange RDPSVC
den produktiven Clientpfad noch nicht ueber R4TLS `op22`/`op23` und
`op24`/`op25` fuehrt. Der Dienst bleibt Consumer von R4TLS und R4AUTH; die
fehlenden Wire-Schichten sind als 0.55.36 bis 0.55.39 geplant.
Seit 0.55.36 besitzt RDPSVC den TLS-Wire-Adapter fuer echte Client-Records:
Nach `HYBRID_EX` liest der Dienst den TLS ClientHello direkt vom TCP-Stream,
uebergibt ihn an R4TLS `op22`, sendet die Server-Handshake-Records, sammelt
ClientKeyExchange, CCS und Finished, ruft R4TLS `op23` auf und sendet danach
Server-CCS/Finished. Der erzeugte `R4LK`-Stream-State wird nur als Bytevertrag
gehalten; RDPSVC parst ihn nicht und baut weiter keine eigene TLS-
Kryptografie. Fuer die naechsten Schritte sind `tlsWireWrite`/`tlsWireRead`
als Kapsel um R4TLS `op24`/`op25` vorhanden. `SERVMAN STATUS RDPSVC` zeigt
`tls_wire`, `tls_records`, `tls_app` und `tls_wire_errors`.
R4TLS verlangt fuer diesen TLS-1.2-Pfad keinen TLS-1.3-`key_share` im
ClientHello; der Client-Public-Key kommt aus ClientKeyExchange in `op23`.
Seit 0.55.37 fuehrt RDPSVC die CredSSP-Live-Schleife ueber genau diesen
R4TLS-Wire-Adapter. Der Dienst liest Negotiate, Authenticate und PubKeyAuth
ueber `tlsWireRead`, baut nur den `R4CL`-Rahmen mit opakem `R4LK`, ruft R4AUTH
`op19` auf und schreibt die von R4AUTH `op12` erzeugte NTLM-Challenge ueber
`tlsWireWrite` zurueck. Die feste Anmeldung bleibt `r4os`/`rosebud`;
Bad-Password, Bad-PubKeyAuth, Kerberos, Domain und Bad-TSRequest werden als
sichtbare Fehlerpfade gezaehlt. RDPSVC besitzt weiterhin keinen privaten
TSRequest-, SPNEGO-, NTLM- oder PubKeyAuth-Parser.
Seit 0.55.38 fuehrt RDPSVC nach diesem CredSSP-Live-Loop auch die
RDP-Aktivierung ueber denselben verschluesselten Stream. `RdpTransport`
kapselt Plain-TCP und R4TLS-Application-Records, so dass Classic-RDP und
Modern-RDP denselben `runRdpActivation`-Pfad fuer MCS, ClientInfo,
Demand/Confirm Active, Font Map, Bitmap-Updates und Input nutzen. Der Host-
Harness prueft dafuer `modern-wire` mit Initial-Bitmap und Input-Bitmap ueber
Windows/.NET `SslStream`; `modern_stream` wird erst nach diesem Abschluss
gezaehlt.
Die finale echte Windows-`mstsc.exe`-End-to-End-Sichtabnahme bleibt ein
spaeterer Abnahmeschritt.
Seit 0.55.39 wird diese Sichtabnahme ueber
`Tests/Runtime/Run-RdpMstscManual05539.ps1` vorbereitet. Das
Script startet QEMU headless mit RDPSVC-Testkonfiguration, schreibt das
Modern-NLA-Profil und startet `mstsc.exe` nur mit explizitem `-LaunchMstsc`.
Nach zwei echten mstsc-Sitzungen mit Login, Bitmap, Eingabe, Abbruch und
Reconnect wertet es die RDPSVC-Logmarker fuer TLS-Wire, CredSSP-Live,
geschuetzte Aktivierung, Bitmap-Frames und Reconnect aus.
Der erste echte mstsc-Versuch am 2026-06-26 kam bis zur Passwortannahme und
brach danach mit `0x904`/`0x7` ab. RDPSVC behandelt deshalb in der
Post-CredSSP-Aktivierung jetzt den vom Client angekuendigten
`CS_NET`-Kanalblock: User- und I/O-Channel plus alle statischen mstsc-Kanaele
werden als MCS-Channel-Joins bestaetigt. Der Host-Harness sendet passend zur
Fixture fuenf Joins, damit der Fehler nicht wieder durch den Test rutscht.
Ein zweiter mstsc-Versuch am 2026-06-26 17:40:33 UTC kam ebenfalls bis zur
Passwortannahme und brach danach erneut mit `0x904`/`0x7` ab. RDPSVC haertet
deshalb den folgenden Server-Demand-Active-PDU: Der Dienst sendet jetzt einen
vollstaendigeren Capability-Satz mit Share, General, Bitmap, Order, Control,
Activation, Pointer, Color Cache, Input, Font und Virtual Channel und nutzt im
Share-Control-Header den User-Channel als `pduSource`. Der Transport bleibt
auf dem I/O-Channel. 0.55.39 ist erst nach echtem Windows-`mstsc.exe`-Pass
abgeschlossen.
Ein dritter mstsc-Versuch am 2026-06-26 18:58:50 UTC zeigte denselben Fehler.
RDPSVC sendet deshalb zwischen Client Info und Demand Active jetzt einen
Licensing-Error-Alert `STATUS_VALID_CLIENT`/`ST_NO_TRANSITION`. Das bestaetigt
den Client protokollkonform als gueltig, ohne R4OS eine Lizenz-, Rechte- oder
Userverwaltung zu geben. `SERVMAN STATUS RDPSVC` meldet diesen Schritt als
`license=`.
Ein vierter mstsc-Versuch am 2026-06-26 19:27:59 UTC brach weiterhin nach der
Passwortannahme mit `0x904`/`0x7` ab. RDPSVC schreibt deshalb nun bei jedem
erfolgreichen Aktivierungsmeilenstein einen Trace. `SERVMAN STATUS RDPSVC`
zeigt den letzten Schritt als `trace=`, LOGSVC erhaelt einen Service-Record und
der serielle QEMU-Log bekommt, wenn der Host ihn spiegelt, einen
`RDPSVC trace`-Marker. Die manuelle Abnahmehilfe extrahiert `last_trace`,
`last_lifecycle` und `last_session_done` in ihren Report, damit der naechste
Protokollfix auf der realen R4OS-Abbruchkante basiert.
Ein weiterer QEMU-GUI-Lauf am 2026-06-27 kam wieder bis zur
Passwortannahme und brach danach ab, waehrend `qemu-gui.log` nur bis
`Launcher [START]` reichte. Darum schreibt RDPSVC jede Aktivierungsstage nun
zusaetzlich als eigenen LOGSVC-Record `trace stage=...`; dieser Pfad ist fuer
manuelle Build.bat-GUI-Tests wichtiger als der serielle Hostlog.
Der RDPSVC-Selftest schreibt dafuer zusaetzlich einen klar markierten
`trace stage=selftest`-Record nach LOGSVC. `Run-LogCenterRdpTraceExport05539.ps1`
bootet ein Testimage, fuehrt den Selftest aus und prueft, dass
`LOGCENTER.R4X /RDPTRACE` diesen Record nach `C:\TEMP\RDPTRACE.TXT`
exportiert.
Der Nutzerlauf am 2026-06-28 08:41:20 UTC zeigte erstmals die exakte
Vorkante vor MCS: `SERVMAN STATUS RDPSVC` meldete `selected=8`, `mcs=0`,
`credssp_wire=0/0/0` und `compat_blocker=credssp-bad-tsrequest`. R4AUTH
akzeptiert seitdem TSRequest-Versionen 2 bis 6 und kennt einen
Windows-naeheren Final-TSRequest mit `authInfo` plus verschluesseltem
`pubKeyAuth`. RDPSVC bleibt dabei Consumer: Der Dienst wertet nur
`complete=yes` aus und fuehrt danach denselben geschuetzten RDP-
Aktivierungspfad weiter.
RDPSVC ist ausserdem gegen Abbrueche entkoppelt, die sonst TCPSVC und damit
andere Connectivity-Dienste verhungern lassen koennen: Accept, Read, Write,
Poll, Retransmit, Close und Listener-Close laufen ueber bounded
TCPSVC-Servicecalls am Service-Handle; der Session-Cleanup nutzt bounded Close
mit Abort-Fallback. `Run-RdpSshCoexistence05539.ps1` prueft, dass SSH vor und
nach drei synthetischen mstsc-modern-Abbruechen erreichbar bleibt.
Seit 0.55.47 sendet RDPSVC den MCS-Server-Network-Block passend zum Client-
`CS_NET`: der I/O-Channel und alle statischen Kanaele werden im Connect
Response gemeldet, Attach User Confirm nutzt den PER-User-Channel-Offset und
Channel Join Confirm bestaetigt Initiator, Requested Channel und Joined
Channel. Die Session-Worker reservieren wie SSHD 2 MB Stack, weil die moderne
TLS-/CredSSP-/Aktivierungskette grosse R4X-Frames nutzt. Der Live-Test
`Run-RdpServiceLiveTest.ps1` deckt Classic, Reconnect, TLS-Wire,
CredSSP-Live, geschuetzte Modern-Aktivierung mit Bitmap/Input, Negativpfade,
Invalid-Packet und die `mstsc-modern`-Negotiation-Probe ab.
Der Nutzerlauf am 2026-06-28 09:11:29 UTC erreichte die Windows-
Zertifikatswarnung. Nach Zustimmung waehlt mstsc in diesem Lauf
`selectedProtocol=SSL/TLS-only` (`selected=1`) und sendet TLS-AppData, aber
RDPSVC beendete die Sitzung noch als `tls-wire-ok`, bevor MCS begann.
RDPSVC fuehrt diesen TLS-only-Pfad jetzt ebenfalls in die geschuetzte
Aktivierung ueber R4TLS-Application-Records. Der fokussierte Live-Test
`Run-RdpServiceLiveTest.ps1 -TlsOnlyProtectedOnly` prueft X.224-SSL-Auswahl,
TLS-Wire, Bitmap und Input auf diesem Pfad.
Der Nutzerlauf am 2026-06-28 09:54:23 UTC verschob die Kante bis direkt nach
MCS Connect Response: mstsc meldete Authentifizierungsfehler `0x609`,
`SERVMAN STATUS RDPSVC` zeigte `trace=mcs-response`, `mcs=1`, `mcs_resp=1`,
aber noch kein Erect Domain. RDPSVC spiegelt im Server Core Data Feld
`clientRequestedProtocols` deshalb jetzt die tatsaechlich vom Client
angeforderten RDP-Negotiation-Flags statt immer `0`. Der Live-Test prueft
Classic `0`, HYBRID_EX `0x0000000B` und TLS-only `0x00000001`.
Der Nutzerlauf am 2026-06-28 10:25:29 UTC erreichte danach alle MCS-Schritte
bis `trace=channel-joins`: Erect Domain, Attach User und sechs Channel-Joins
waren bestaetigt, Client Info aber noch nicht. RDPSVC akzeptiert seitdem einen
optionalen Security Exchange PDU (`SEC_EXCHANGE_PKT`) vor Client Info, zaehlt
ihn als `sec_exchange` und liest Client Info danach aus dem MCS-UserData-
Payload. Der TLS-only-Livetest sendet diese mstsc-nahe Sequenz jetzt explizit
vor Client Info.
Der Nutzerlauf am 2026-06-28 11:10:33 UTC kam danach bis
`trace=license-valid-client`: Client Info und Licensing waren sichtbar, Demand
Active aber noch nicht. Windows meldete nun `0x2904`. RDPSVC baut deshalb den
serverseitigen MCS-`SendDataIndication`-Header zentral und sendet dort den
User-Channel-Offset `1` als Initiator sowie den I/O-Channel `1003` als Ziel.
License Valid Client, Demand Active, Share-Data-PDUs und Bitmap-Frames nutzen
damit denselben mstsc-naeheren Wrapper; der Host-Livetest prueft License und
Demand Active explizit auf diesen Header.
Der anschliessende Full-Harness erreichte bereits Classic-, Reconnect-,
Modern-Wire- und TLS-only-Bitmaps, lief dann aber in einem RDPSVC-Worker-
Page-Fault mit `rip=0`. RDPSVC reserviert fuer Session-Worker deshalb jetzt
4 MB Stack, damit die grossen TLS-/CredSSP-/Aktivierungsframes nicht erst in
spaeten Negativpfaden den Rueckkehrpfad korrupt machen.
Nach dieser Haertung lief der vollstaendige RDPSVC-Live-Harness durch:
Classic, Reconnect, Modern-Wire, TLS-only, Bitmap/Input sowie CredSSP-
Negativpfade wurden ohne Crash bestaetigt.
Der Nutzerlauf am 2026-06-28 12:53:09 UTC verschob die Kante bis
`trace=demand-active`: Client Info, Licensing und Demand Active waren sichtbar,
Confirm Active aber noch nicht. RDPSVC behandelt geschuetztes RDP ueber TLS
deshalb jetzt als Byte-Stream und extrahiert RDP-TPKTs ueber einen eigenen
Pending-Puffer. Wenn Windows mehrere TPKTs in ein TLS-ApplicationData-Record
legt, bleiben die uebrigen Bytes fuer den naechsten RDP-Read erhalten, statt
als Protokollfehler verworfen zu werden. Der Live-Harness reproduziert das mit
einem Post-Demand-Batch aus Confirm Active, Sync, Control und FontList.

Der Nutzerlauf am 2026-06-28 13:37:58 UTC blieb danach noch bei
`trace=demand-active`, `confirm=0`. RDPSVC behandelt die Connection
Finalization deshalb nicht mehr als starre Einzel-Reads, sondern als
MS-RDPBCGR-nahe Zustandsphase: Confirm Active, Server Synchronize/Control
Cooperate, Client Synchronize, Client Control Cooperate/Request Control,
optionale Persistent Key List, Font List und anschliessend Server Font Map.
Share-Data-Header werden serverseitig mit `uncompressedLength = pduType2/
Compression-Felder + Body` gebaut; der Parser akzeptiert zur Diagnose alte
Body-only-Laengen weiter. Granted Control enthaelt jetzt `grantId=1002` und
`controlId=1002`. Der Live-Harness prueft die konkreten Bodies und bestaetigte
danach TLS-only-protected sowie den kompletten Classic/Reconnect/Modern-Wire/
CredSSP-live/TLS-only/Negative-Pfad bis Bitmap/Input.

Die echten Nutzerlaeufe am 2026-06-29 09:32:53 UTC, 11:01:29 UTC, 11:35:19 UTC
und 12:12:59 UTC blieben trotzdem bei `trace=demand-active`, `confirm=0`.
Damit kommt Windows nicht bis zur Connection-Finalization; der Server-
Demand-Active-PDU beziehungsweise die unmittelbar davor gesendete License-
Valid-Client-PDU ist die naechste Protokollkante. Der XRDP-Abgleich zeigte
danach zwei schaerfere Korrekturen: License Valid Client nutzt jetzt wie XRDP
`SEC_LICENSE_PKT | SEC_LICENSE_ENCRYPT_CS` (`0x0280`), und Demand Active
bewirbt keine ungetragenen FastPath-/RemoteApp-Faehigkeiten mehr. RDPSVC sendet
jetzt ein ehrliches XRDP-Produktivprofil: 10 Capability-Sets, `RDP\0` als
Source Descriptor, Share-Pad `b5 e2`, General `extraFlags=0x0400`, Bitmap,
header-only Font, Order mit Rev3-Cache-Flags `0x000006a1/0x0002`,
Bitmap-Codecs, Color Cache, Pointer, Input-Flags `0x0115` und Bitmap-Cache-
Rev3-CodecId. Der Wire-Harness und das 0.55.39-Gate pruefen diese Werte und
blockieren RAIL/Window/DrawGdiPlus/VirtualChannel-Werbung, solange diese Pfade
nicht wirklich implementiert sind. Die echte Sichtabnahme bleibt bis zum
Windows-`mstsc.exe`-Pass offen.

Manuelle Sichtabnahme:

    DevTools\Scripts\Build.bat -gui
    DevTools\Logs\RdpProfiles\R4OS-Modern-NLA.rdp

Benutzer `r4os`, Passwort `rosebud`.

Profilhilfe fuer Host-Tests:

`Build.bat -gui`, `-qemu` und `-guionly` schreiben reproduzierbare
`.rdp`-Profile nach `DevTools\Logs\RdpProfiles\`. `Classic` ist der
vorhandene R4OS-Classic-Pfad ohne NLA/CredSSP. `Modern` erzwingt den
aktuellen mstsc-Zielpfad. Seit 0.55.29 ist der erwartete TLS-Alert aus dem
RDPSVC-Happy-Path entfernt; die vollstaendige Windows-mstsc-End-to-End-
Sichtabnahme mit Hostforwarding und LAN-nahem Profil bleibt ein spaeterer
Abschluss.

Wenn Windows mstsc NLA/CredSSP erzwingt, laeuft der Verbindungsversuch seit
0.55.21 in die R4TLS/R4AUTH-Route. Seit 0.55.29 ist der erwartete
Happy-Path-Alert entfernt; interne Readiness-Blocker bleiben Statusdaten,
echte TLS-Wire-Fehler duerfen weiter einen R4TLS-Alert ausloesen. Fuer den
Classic-RDP-Test eine `.rdp`-Datei mit
mindestens diesen Werten verwenden:

    full address:s:127.0.0.1:13389
    username:s:r4os
    authentication level:i:0
    enablecredsspsupport:i:0
    negotiate security layer:i:0

Falls mstsc trotzdem vor der klassischen Aktivierung abbricht, ist das kein
R4OS-Sicherheitsmodellproblem, sondern der naechste echte RDP-
Kompatibilitaetsschritt: TLS/NLA/CredSSP oder eine nachweisbar von mstsc
akzeptierte Classic-RDP-Konfiguration.

Registry-Defaults:
- `Enabled=ON`
- `ListenPort=3389`
- `ClientTarget=WindowsMSTSC`
- `UserName=r4os`
- `Password=rosebud`
- `MaxSessions=1`
- `LogPasswords=ON`

Hardware-Geometrie seit 0.59.6
--------------------------------

Der reale Lenovo-Lauf erreichte Login und aktive RDP-Sitzung, blieb danach
aber schwarz. Ursache war kein TLS-/MCS-Fehler: `sendBitmapFrame` lehnte jede
Remote-Frame-Breite oberhalb von 1280 Pixeln ab. Der Laptop-Desktop laeuft mit
1920x1080, sodass nach Font Map kein einziges Bitmap gesendet wurde.

RDPSVC liest die gueltige R4DESK-Frame-Geometrie nun vor Demand Active und
kuendigt genau diese Breite/Hoehe als Sitzungsdesktop an. Vollbildstreifen,
Dirty-/Cursorrechtecke und absolute Mauseingaben verwenden dieselbe Grenze;
ein spaeterer Geometriewechsel wird geloggt und beendet die Sitzung
kontrolliert. Unterstuetzt werden Sitzungsachsen bis 8192 Pixel.

Der Sender besitzt keinen auf die Framebreite skalierten Zeilenpuffer mehr.
Shared Mapping und `remoteFrameRead` arbeiten in maximal 256 Pixel breiten
Kacheln. RLE16 verarbeitet den durch vier teilbaren Anteil. Bei Breiten wie
1365/1366 werden die letzten 1 bis 3 Pixel als unkomprimiertes RGB565-
Rechteck mit 4-Byte-Zeilenpadding angehaengt; damit bleibt die gesamte als
16 bpp angekuendigte Sitzung formatkonsistent.

Jede Session schreibt sofort einen kompakten `rdp geometry`-Record nach
LOGSVC. Bitmap-Records enthalten Region, Revision und `nonblack`: `0` bedeutet
fuer genau die gesendete Region tatsaechlich nur schwarze RGB-Pixel. Der
Checksum dient nur noch als positionssensitiver Aenderungswert. Abruf:

    LOGCENTER.R4X /RDPTRACE

Das permanente `Run-RdpBitmapGeometryContract0596.ps1`, der RDPSVC-Selftest
und `Run-RdpServiceLiveTest.ps1` pruefen Geometrien, Raw16-Rand, PDU-Budgets,
Demand Active, Bitmap/Input und die bestehenden Classic-/TLS-/CredSSP-Pfade.
