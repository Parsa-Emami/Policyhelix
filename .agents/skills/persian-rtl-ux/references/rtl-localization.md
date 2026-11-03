# Persian RTL reference

Access review: 2026-10-03, research browser. Verify the actual target framework/version when applying these sources.

| Source | Application | Review status and boundary |
|---|---|---|
| [W3C Arabic & Persian Layout Requirements](https://www.w3.org/TR/alreq/) | Script layout and shaping context | Read; Group Draft Note 2025-10-02, not a W3C Recommendation |
| [W3C structural markup and RTL](https://www.w3.org/International/questions/qa-html-dir) | Semantic HTML direction, boundaries and unknown-direction content | Read; lang and dir serve distinct purposes |
| [Unicode CLDR Persian](https://cldr.unicode.org/translation/language-specific/persian) | Persian letters, display digits and separators | Read; does not prescribe product calendar/currency choices |
| [Unicode UAX #9](https://www.unicode.org/reports/tr9/) | Logical text storage and bidi display | Read; revision 52, Unicode 18.0.0, 2026-09-01; runtime support may differ |
| [Android localization](https://developer.android.com/guide/topics/resources/localization) | Resources and locale handling | Read; platform-specific |
| [Android language and RTL support](https://developer.android.com/training/basics/supporting-devices/languages) | Direction-aware native layouts | Read; verify target APIs and test on device |
| [Apple HIG RTL](https://developer.apple.com/design/human-interface-guidelines/right-to-left) | Candidate native Apple guidance | Partial: JavaScript shell only; recommendation body unverified here |

## Web decisions

- Put `lang="fa"` and `dir="rtl"` at the Persian document boundary. A multilingual subtree can have its own language/direction. CSS direction alone does not replace semantic markup.
- Use logical properties such as margin-inline-start, padding-inline and text-align:start. Preserve logical DOM order so reading and keyboard order follow content meaning.
- Known LTR identifiers can use a direction-isolating element such as `<bdi dir="ltr">`. For unknown-direction user content, choose isolation/dir=auto suited to context and test first-strong-character edge cases.
- Keep phone/email/URL inputs usable and labels Persian. Decide input direction and parsed representation per field; Persian display digits are not a requirement to rewrite identifiers.
- Preserve explicit amount units. An IRR amount represents rial; a toman display requires explicit conversion and product agreement. Avoid formatting a toman value as IRR.
- Store timestamps as instants/appropriate domain values. Select display timezone/calendar deliberately; a Persian locale alone must not silently change a scheduling contract.
- Mirror reading-direction controls where meaning requires it. Review each icon; do not mirror brand marks or arbitrary images by blanket CSS transforms.

## Locale, form and transaction boundaries

Separate Persian language from regional behavior. Choose locale variants, numbering system and calendar with the product contract; CLDR is locale data, not a mandate that all Persian users share Iran's operating terms. For Tehran scheduling use the named zone Asia/Tehran when selected, with maintained runtime timezone data. [IANA Asia source](https://data.iana.org/time-zones/tzdb/asia), read 2026-10-03, records historical rule changes; adding a fixed offset is not a general timezone conversion algorithm.

For numeric entry, decide per field whether Latin 0123456789, Persian ۰۱۲۳۴۵۶۷۸۹ and Arabic-Indic ٠١٢٣٤٥٦٧٨٩ are accepted. When allowed, parse a separate canonical value at the field boundary. Keep leading zeroes for OTPs, phones, postal codes and identifiers; these are strings, not arithmetic numbers. Preserve free text, names, passwords and original evidence. A visual digit substitution is not validation.

For a phone field define accepted domestic/international forms and normalization with the backend; inputmode is a keyboard hint, not proof of validity. Permit editing/paste according to that contract. For an address choose fields based on fulfillment area and actual provider requirements; Iranian examples should not force +98 or an Iranian postal contract on other Persian locales.

Keep display amount, stored amount and gateway request unit explicit. [Zarinpal currency](https://www.zarinpal.com/docs/paymentGateway/moreFeatures/currency) and [connection guide](https://www.zarinpal.com/docs/paymentGateway/connectToGateway), read 2026-10-03, illustrate IRR/IRT requests and separate payment verification. IRT here is a provider API value, not a general ISO/schema currency code. Confirm the chosen API/SDK's request and verify contracts, especially where documentation labels differ; do not guess conversion or default units.

Map UI states to the backend's actual payment/order states: pending confirmation, confirmed, canceled/failed and unresolved. Preserve order/reference identifiers and use an existing safe status-check action before offering another payment. Callback arrival alone is not success. Report backend behavior unverified when unavailable; this UX skill does not authorize building or executing a new payment integration.

Test the selected fonts for Persian shaping, ی/ک, half-space, combining marks, digit legibility, line height and fallback under loading/zoom. Match typography to the existing brand and target readability; do not mandate one font or a universal point size.

## Iranian implementation contracts

Use these checks only for an Iranian target agreed in the brief. A Persian interface for another region keeps its own contract.

- **Money:** under the conventional product contract here, 1 toman = 10 rial. Carry an explicit unit with every amount: 250,000 toman is 2,500,000 rial. Keep displayed, stored, request and verify amounts separate. Convert once at the defined boundary; do not multiply again inside an SDK already converting. Use exact decimal/integer arithmetic appropriate to the contract, not floating-point approximations. A rial value not divisible by 10 needs an explicit fractional-toman/rounding decision; never silently discard value. Reconcile item totals, shipping, fees and discount before payment. Currency selectors/API defaults must come from the actual SDK/provider version, not from the word Persian. IRT is a provider token, not a universal structured-data currency code.
- **Digits and identifiers:** accept agreed digit sets for amount/phone/OTP entry and preserve raw values where needed. Separate grouped display from parsing: reject ambiguous separators according to the field contract. Phone, OTP, postal code, order ID and national/bank identifiers are strings, not arithmetic numbers. Do not normalize passwords, names or evidence in place. Search keys may separately fold Arabic/Persian letter variants and half-space.
- **Iran mobile:** domestic `09120000000` and international `+989120000000` denote the same synthetic example under the agreed mobile-number contract; omit the domestic trunk zero after +98. Parsing/format alone does not establish ownership or reachability. Use maintained numbering metadata and backend rules rather than a permanently hard-coded list of operator prefixes. See the [ITU Iran numbering index](https://www.itu.int/oth/T0202000066/en); index read 2026-10-03, listed attachment body not reviewed in this pass.
- **SMS sign-in:** enforce code length, expiry and resend timing on the server. Allow paste/autofill where supported, mask the destination appropriately, preserve code-leading zeroes and distinguish incorrect code from expired code and delivery delay. Review account recovery/accessibility without collecting extra identity merely to localize.
- **Calendar:** when selected, show Solar Hijri dates in Asia/Tehran while preserving the original instant or date-only booking meaning. Test midnight, year transitions and invalid dates with a maintained library. Business-day deadlines require the provider's holiday schedule; do not infer a universal weekend/working-hour rule.
- **Address:** choose province/city/service area, address, plaque/unit and postal fields from fulfillment needs. Treat postal-code shape as syntax, not proof of address or serviceability; verify provider rules before hard-coding. Keep entered address when city eligibility changes. GNAF was inaccessible in the 2026-10-03 review; no detailed postal validation rule is certified here.
- **Interrupted checkout:** a timeout or delayed bank SMS is not confirmed failure. Preserve cart/form/order reference; use the existing status/recovery contract and server protection against duplicate charge or order. Do not implement or execute real payment just to demonstrate the UX. Account for low bandwidth, delayed assets and SMS as test conditions, not a claim about all Iranian users.

Completion evidence: show the money conversion boundary and expected totals; record phone/OTP strings, date/zone, eligibility and recovery cases with actual versus unrun checks.

## Persian articles and content cards

Use real long Persian titles and mixed-script game/product names at target mobile and desktop widths. Check heading order, readable body measure/spacing, wrapping, category labels and whether truncation hides the subject. Source inspection supports a suspected issue; browser checks establish only the tested widths/states.

Inspect thumbnails at the actual card dimensions and crop, not only as large source files. Prefer a recognizable subject, clear contrast and little necessary text; tiny screenshots often lose the detail that makes a tutorial understandable. Keep authentic screenshots in instructional passages where needed. Generated covers are illustrations, not verified UI states. Provide informative alt text for meaningful images; avoid repeating nearby captions or exposing sensitive screenshot data.

When a sticky reading header is requested, inspect scrolling containers, overflow ancestors, stacking and available space before proposing CSS. Check scroll behavior, anchor/focus targets, visible content and mobile height in the runtime. A soft shadow/blur must not obscure text or trap pointer events. Record any untested browser, zoom or assistive-technology behavior; do not claim a universal fix from a static screenshot.
