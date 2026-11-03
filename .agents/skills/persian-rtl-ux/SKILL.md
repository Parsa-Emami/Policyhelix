---
name: persian-rtl-ux
description: Audit or implement Persian interfaces for RTL layout, mixed Persian/Latin text, locale formatting and input behavior. Use when building Persian UI, localizing an interface or fixing bidirectional and responsive UI defects.
license: MIT
compatibility: Runtime verification needs the target browser or app. Source-only and screenshot reviews must label untested behavior.
---

# Persian RTL UX

Preserve content meaning, usable inputs and product requirements. Apply the [evidence policy](references/evidence-policy.md). Read the [RTL reference](references/rtl-localization.md) for platform guidance and [test cases](references/test-cases.md) when verifying mixed text, locale and interaction.

For Iranian projects, read the **Iranian implementation contracts** section in [the task reference](references/rtl-localization.md) when money, payments, phone/SMS, fulfillment or local dates affect the request. Apply relevant checks only; keep other Persian regions and the user’s scope intact.

For articles or content interfaces, read the editorial section of [the task reference](references/rtl-localization.md) when the request concerns local cultural fit, article comparison or reading/card usability. Apply only the relevant checks.

## Workflow

1. **Identify the contract.** Establish audit versus implementation, platform/framework, locale variants and design conventions. Record calendar, timezone, digit and currency requirements; ask where ambiguity affects correctness. Separate language from region and service eligibility. For forms/transactions use the RTL reference’s input and state contracts. RTL alone does not choose these settings.
2. **Fix semantic direction.** Set language/base direction at the correct boundary. Use logical layout properties and isolate embedded text when needed. Preserve source/DOM order and stored text; avoid reversing strings to imitate RTL. Mirror controls whose meaning depends on reading direction, preserving fixed-meaning content such as logos/media controls as appropriate.
3. **Check text and data.** Exercise Persian/Latin names, parentheses, URLs, phone, email, prices and identifiers. Keep identifiers copyable, currency units explicit and numeric values independent of display digits. Normalize a separate search/comparison representation only when needed; preserve original names, passwords, identifiers and user-entered text.
4. **Verify interaction.** Check target responsive widths, long content, focus/keyboard order, labels, error association and available assistive technology. Exercise editing, selection, validation and copy/paste with the reference corpus. For multilingual products check both directions. Record actual environment/results; screenshots cannot verify keyboard, clipboard or screen-reader behavior.
5. **Report or patch.** Tie issues to components and reproducible cases. For implementation, make scoped changes fitting the codebase, rerun affected cases and distinguish confirmed fixes from pending choices. Preserve platform-specific behavior instead of applying web recipes to native UI.

## Deliverable and completion

Return findings or a patch with locations, input cases, expected/observed results, severity and verification status. Include locale decisions and untested checks. Every in-scope issue must be fixed and checked or explicitly reported with evidence and a next action.

For source-only review, report static findings and runtime checks still needed. With no implementation/runtime access, supply a concrete audit without claiming a tested fix. Machine-readable dates, amounts and identifiers must retain their meaning after display changes.
