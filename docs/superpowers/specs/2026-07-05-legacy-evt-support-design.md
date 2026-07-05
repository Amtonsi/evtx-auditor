# Windows XP EVT Support Design

## Goal

EVTX Auditor must remain one desktop application and one HTML report generator, while accepting both modern Windows `.evtx` logs and legacy Windows XP / Server 2003 `.evt` logs from ZIP archives.

## Scope

- ZIP discovery stays unchanged: node folders contain one or more ZIP archives.
- Archive extraction must include `.evtx` and `.evt`.
- `.evtx` continues to use `python-evtx`.
- `.evt` uses Windows classic Event Log backup reading through `pywin32` (`win32evtlog.OpenBackupEventLog` / `ReadEventLog`).
- Both formats normalize into the existing `EventRecord` model and existing analyzer/report flow.
- HTML remains a single offline file with one section per node.
- Report evidence must show whether a record came from `EVTX` or `EVT`.

## Legacy XP Rules

Windows XP security events use pre-Vista Event IDs. Add explicit rules for:

- audit log cleared: `517`;
- failed logons: `529`, `530`, `531`, `532`, `533`, `534`, `535`, `536`, `537`, `539`, `680`;
- user lifecycle: `624`, `630`, `642`, `644`;
- group membership changes: `632`, `633`, `636`, `637`, `660`, `661`.

Generic `Error` and `Critical` level handling still applies where the legacy event type maps to those levels.

## Limitations

Archived XP `.evt` logs may not render the full provider message on a modern machine if the original XP message DLL is unavailable. In that case the report still keeps Event ID, source/provider, computer, time, category, event type, record number and insertion strings.

## Verification

- Unit tests must prove `.evt` entries are extracted from ZIP archives.
- Unit tests must prove legacy event records normalize into `EventRecord`.
- Unit tests must prove XP security Event IDs classify correctly.
- Full pytest suite and PyInstaller build must pass before delivering updated `outputs`.
