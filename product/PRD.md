# PolicyHelix product requirements v0

Status: planning; application source not implemented. English-facing app/docs are the release default. See Persian assessment for commercial hypotheses.

Target user: توسعه‌دهندهٔ چند سرویس شخصی و تیم کوچک

Job to complete: policy-as-code قابل‌تست با توضیح تصمیم و rollout کنترل‌شده

Differentiation hypothesis: simulator و diff تصمیم با OIDC موجود، برای یک اپ تحت مالکیت خودت

## MVP acceptance scope

- CLI simulator policy و fixtures
- OPA adapter با bundle نسخه‌دار
- یک gateway خصوصی برای یک upstream
- OIDC موجود و session revocation پایدار

## Excluded until another decision

- IdP اختصاصی
- مش چند region
- SPIFFE/SPIRE
- Envoy adapter و SaaS multi-tenant

## End-to-end outcomes

1. fixture policy در simulator نتیجهٔ expected بدهد و دلیل deny مشخص باشد
2. origin مستقیم و header جعلی identity مسیر دسترسی نسازند
3. decision/IdP outage، revoke و bundle قدیمی باید رفتار fail-closed مستند داشته باشند

Functional requirements F01–F20 and nonfunctional/release requirements are mapped one-to-one in `plans/requirements.json`. Tests belong with their feature commit, not postponed until launch. Success: a clean installed selected profile performs the core task and recovers from documented failures. Public demand remains unvalidated until real trials are recorded.

## UI flow

Select/import scoped input -> validate limits and permission -> show actual processing state -> explain result and confidence -> review/triage where appropriate -> export -> recover in clean environment. Loading, empty, stale, partial, unauthorized, rejected input, timeout/cancel and permanent failure are explicit. Provide table/keyboard alternatives to canvas, charts and graph paths. No sensitive content in page telemetry.
