# PolicyHelix: reference workflow

Status: planned domain acceptance; the current JSON structure preview does not implement this workflow.

Simulator fixture -> sign/verify bundle -> protect owned upstream -> test spoofed header/direct origin -> revoke -> simulate decision/IdP outage and expired policy.

Required invariants:

- Private resources fail closed
- Only authenticated normalized identity enters policy
- Bundle signature plus freshness and monotonic revision

Required UAT:

- fixture policy در simulator نتیجهٔ expected بدهد و دلیل deny مشخص باشد
- origin مستقیم و header جعلی identity مسیر دسترسی نسازند
- decision/IdP outage، revoke و bundle قدیمی باید رفتار fail-closed مستند داشته باشند

Machine contract: tests/scenarios/clone-to-value.json. C01/C04 create and freeze the actual synthetic positive/negative fixture formats; no real secrets, user source/traffic/case data or unlicensed corpus. A clean source clone must reproduce the entire workflow with restart and restore at C30.
