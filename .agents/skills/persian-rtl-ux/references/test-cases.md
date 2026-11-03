# Persian interface test corpus

Select cases relevant to the component. Record runtime/browser/device, viewport, input, expected behavior, actual result and verification method. These strings are synthetic fixtures, not user data.

| Case | Sample | Expected invariant |
|---|---|---|
| Mixed brand/model | گوشی Samsung Galaxy S24 (نسخهٔ 256GB) | Words, model and parentheses retain meaning |
| Phone | +98 912 000 0000 | Digit/sign order and copied value remain intact |
| Email | support@example.com | Latin order, editable input and copy/paste preserved |
| URL | https://example.com/product?id=42 | Delimiters and query order stay usable |
| Order identifier | سفارش AB-123/45 | Identifier remains intact within Persian prose |
| Amount | ۱٬۲۵۰٬۰۰۰ تومان | Explicit unit; numeric value unaffected by display formatting |
| Decimal | ۱۲٫۵ | Parser/display behavior matches specified locale |
| Letter variants | كي / کی | Search may normalize a separate key; original stored content remains intact |
| Half-space | می‌روم / میروم / می روم | Search policy can compare variants; names/free text stay verbatim |
| Untrusted user text | Alice گفت: (سلام) | Content is rendered safely and isolated appropriately |
| Long content | A long Persian title with SKU AB-123 | Wraps without hiding actions or changing identifier meaning |
| Date/time | A known supplied instant near midnight | Agreed timezone/calendar; machine value remains the same |

## Interaction checks

- At narrow/wide target widths, check overflow, truncation, action order and readable long content.
- Tab through interactive controls; inspect focus, label/error association and semantic DOM order. A visual RTL position alone does not dictate reversed tab order.
- Enter Persian and Latin digits in numeric fields where supported; check validation, editing, selection and copied values. Preserve leading zeroes on identifiers.
- Exercise screen-reader labels when a reader is available; otherwise label them statically reviewed and runtime untested.
- For bilingual products switch language and repeat affected cases.
- Capture failures before changes and rerun the same cases after. Mark a source-only review as source-only.

## Small web pattern

```html
<html lang="fa" dir="rtl">
  <p>سفارش <bdi dir="ltr">AB-123/45</bdi></p>
  <label for="phone">شمارهٔ تماس</label>
  <input id="phone" type="tel" dir="ltr" autocomplete="tel">
</html>
```

This pattern demonstrates boundaries; it is not a complete application or a tested guarantee for every browser. Keep the app's existing validation, security and locale contract.

## Local input and state cases

| Case | Synthetic input/state | Check |
|---|---|---|
| Three digit sets | 0123 / ۰۱۲۳ / ٠١٢٣ | Under an accepting field contract, canonical string is 0123; leading zero survives |
| Phone forms | 09120000000 / +989120000000 | Accept/reject and canonical value match the backend contract; never infer an active real number |
| Unresolved gateway return | Callback arrived; confirmation still unknown | No success claim or unsafe duplicate-payment CTA; keep order ID and actual status-check action |
| Calendar boundary | Supplied instant around local midnight/year boundary | Format using chosen calendar/zone and verify against supported runtime; avoid handwritten leap-year shortcuts |
| Address availability | Selected city outside supplied service area | Clear eligibility explanation; preserve non-sensitive entered details |
| Shaping/font fallback | می‌روم، کی، یِ، ۰۱۲۳; delayed font loading | No broken joins/clipped marks; readable fallback, zoom and wrapping |

For amount tests, record a known stored value and expected display/request values using the explicitly agreed conversion; never derive the contract from a screenshot. Simulated interrupted-network tests measure the fixture's recovery behavior, not national network conditions.

## Additional synthetic Iranian contract cases

| Input/contract | Expected invariant |
|---|---|
| Store rial 2500000; display toman | Display ۲۵۰٬۰۰۰ تومان; IRR request remains 2500000 when the provider contract requires rial; convert only once |
| Store rial 2500001 | Ask for fractional/rounding policy; do not silently floor to 250000 toman |
| Item 250000 toman + shipping 30000 | Final total 280000 toman; do not treat unknown shipping as zero |
| Accepted phones 09120000000 / +989120000000 | Equivalent canonical Iranian mobile under agreed parsing; do not retain trunk zero after +98 |
| OTP ۰۱۲۳ / ٠١٢٣ / 0123 | Canonical string 0123; ownership/expiry not inferred |
| Booking instant near Tehran midnight | Same instant; selected calendar/zone display, with day-boundary check |
| Date-only booking | Preserve selected service date; do not accidentally shift through UTC conversion |
| Address city changes outside coverage | Explain ineligibility, preserve address and identify available recovery |
| Network timeout after submit | Unresolved state until verified; retained order and actual duplicate-prevention/status contract |

These are expected cases, not new runtime test results.
