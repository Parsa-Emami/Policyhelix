# PolicyHelix acceptance gate

All scenarios are unexecuted in v0. Use synthetic or explicitly authorized owned data.

1. fixture policy در simulator نتیجهٔ expected بدهد و دلیل deny مشخص باشد
2. origin مستقیم و header جعلی identity مسیر دسترسی نسازند
3. decision/IdP outage، revoke و bundle قدیمی باید رفتار fail-closed مستند داشته باشند

Also require negative input/auth tests, crash or interrupted operation, clean install/upgrade, export/restore and workload bounds. Claims must match selected private/public distribution profile.
