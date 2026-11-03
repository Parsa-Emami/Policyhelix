# PolicyHelix: agent entry point

Read START_HERE.md, docs/agents/EXECUTION_CONTRACT.md, docs/architecture/ADR-0003-open-source-local-first.md, plans/project-state.json, plans/progress.json and plans/release-gates.json. Actual code/tests and source-bound evidence determine capability. legacy/v7 and *_V7.md are historical; do not run their bootstrap or revive compulsory services.

1. Inspect Git status, current source/manifests/locks/tests/CI and preserve other work.
2. Run npm run validate:plan and npm run plan -- next; read the returned plans/commits/Cxx.md in full. Complete only unmet dependency-ready criteria.
3. Follow its exact targets, implementation actions, resources, fixtures, negative cases and current/future command labels. Domain belongs in the selected engine, UI in apps/web and adapters at boundaries. No sibling repository imports.
4. Implement a real vertical slice and meaningful regressions. A static example, generic JSON preview, successful placeholder endpoint or mocked durability/auth cannot replace the product feature.
5. Run actual relevant checks, record exact source/tool/provider/fixture identities and command exits/output; update only genuinely verified progress and session handoff. W evidence never certifies a C task.
6. C30 needs full clean-host core workflow/restart/restore. C40 needs authorized published source/artifacts and installed full-workflow proof.

Permanent owner restrictions: do not modify database schemas, migrations, .env files or Dockerfiles. Use compatible ADR-0003 adapters; record a precise blocker if a protected change is unavoidable and continue independent authorized work. Preserve existing code including RiskWeft's optional API, and fix observed CI defects without disabling checks or adding broad analysis ignores.

All core features remain open source with no required paid/cloud account, public domain or sibling clone. Pin compatible upstream licenses/provenance. Never invent versions, tests, customer feedback, deployment or release claims. Routine reversible authorized work needs no repeated approval; a planned task title does not authorize destructive data actions or publication. Implementation guidance and UI are English, with Persian overview in docs/ROADMAP_FA.md. There is no requirement to spawn subagents.

## Local Engineering Skills & Progressive Disclosure

Local engineering skills are stored in `.agents/skills/`. To conserve context window and maintain focus, **never load all skills into context at once**. Follow progressive disclosure: consult [.agents/skills/using-agent-skills/SKILL.md](.agents/skills/using-agent-skills/SKILL.md) for master skill governance, and load only the specific `SKILL.md` needed for the active task phase:

| Task Phase / Trigger | Target Local Skill | Purpose & Operational Standard |
|---|---|---|
| **Skill Orchestration** | [.agents/skills/using-agent-skills/SKILL.md](.agents/skills/using-agent-skills/SKILL.md) | Master decision tree for selecting workflows across the development lifecycle. |
| **Context & Token Hygiene** | [.agents/skills/context-engineering/SKILL.md](.agents/skills/context-engineering/SKILL.md) | Pruning context, token efficiency, rules hierarchy (Rules → Spec → Source → Errors). |
| **Quality Bar / Anti-Slop** | [.agents/skills/constraint-driven-development/SKILL.md](.agents/skills/constraint-driven-development/SKILL.md) | Written quality contracts (`CONSTRAINTS.md`); strictly forbids silencing linters or skipping tests. |
| **Doc-Grounded Verification**| [.agents/skills/source-driven-development/SKILL.md](.agents/skills/source-driven-development/SKILL.md) | Prevents hallucination; ground all code decisions in official documentation. |
| **Planning & Task Breakdown**| [.agents/skills/planning-and-task-breakdown/SKILL.md](.agents/skills/planning-and-task-breakdown/SKILL.md) | Decomposes requirements into dependency graphs and testable task units. |
| **API & Contract Modeling**  | [.agents/skills/api-and-interface-design/SKILL.md](.agents/skills/api-and-interface-design/SKILL.md) | Contract-first design, type boundaries, Hyrum's Law awareness (e.g. C04/C17). |
| **Incremental Implementation**| [.agents/skills/incremental-implementation/SKILL.md](.agents/skills/incremental-implementation/SKILL.md) | Thin vertical slices (`Implement → Test → Verify → Commit`); no large unverified diffs. |
| **Testing & Regression**     | [.agents/skills/test-driven-development/SKILL.md](.agents/skills/test-driven-development/SKILL.md) | Red-Green-Refactor loop; Prove-It pattern for bug reproduction before fixing. |
| **Triage & Broken Builds**   | [.agents/skills/debugging-and-error-recovery/SKILL.md](.agents/skills/debugging-and-error-recovery/SKILL.md) | Stop-The-Line rule and structured root-cause diagnosis over guesswork. |
| **Refactoring & Clarity**    | [.agents/skills/code-simplification/SKILL.md](.agents/skills/code-simplification/SKILL.md) | Simplifying code while strictly preserving exact runtime behavior and tests. |
| **Anti-Overengineering**     | [.agents/skills/thermo-nuclear-code-quality-review/SKILL.md](.agents/skills/thermo-nuclear-code-quality-review/SKILL.md) | Rejects giant files (>1k lines), premature abstractions, and spaghetti conditional growth. |
| **Code Review & Quality**    | [.agents/skills/code-review-and-quality/SKILL.md](.agents/skills/code-review-and-quality/SKILL.md) | 5-axis review: correctness, readability, architecture, security, performance. |
| **Security & Hardening**     | [.agents/skills/security-and-hardening/SKILL.md](.agents/skills/security-and-hardening/SKILL.md) | STRIDE threat modeling, trust boundaries, input validation, fail-closed handling. |
| **Performance & Latency**    | [.agents/skills/performance-optimization/SKILL.md](.agents/skills/performance-optimization/SKILL.md) | Measure-first optimization, synthetic vs RUM, 200ms decision deadline (C28). |
| **Audit Logs & Telemetry**   | [.agents/skills/observability-and-instrumentation/SKILL.md](.agents/skills/observability-and-instrumentation/SKILL.md) | Redacted audit logging without token leaks, operational metrics, diagnostics (C20/C29). |
| **UI Components & Layout**   | [.agents/skills/frontend-ui-engineering/SKILL.md](.agents/skills/frontend-ui-engineering/SKILL.md) | Accessible, responsive React 19 components with tokens; avoids generic AI aesthetic. |
| **Persian / RTL Text**       | [.agents/skills/persian-rtl-ux/SKILL.md](.agents/skills/persian-rtl-ux/SKILL.md) | Bidirectional layout, mixed Persian/Latin strings, locale formatting for docs/ROADMAP_FA.md. |
| **Atomic Commits & Git**     | [.agents/skills/git-workflow-and-versioning/SKILL.md](.agents/skills/git-workflow-and-versioning/SKILL.md) | Trunk-based commits, clean commit boundaries matching C01–C40 cards. |
| **CI/CD Quality Gates**      | [.agents/skills/ci-cd-and-automation/SKILL.md](.agents/skills/ci-cd-and-automation/SKILL.md) | Shift-left automated gates and clean-checkout regression workflows (C06/C39). |
| **ADRs & Architecture Docs** | [.agents/skills/documentation-and-adrs/SKILL.md](.agents/skills/documentation-and-adrs/SKILL.md) | Recording architecture decisions and the "why" matching existing ADR-0003 format. |

### Precedence & Governance Rules:
1. **Contractual Precedence:** Repository rules, permanent owner restrictions (no DB schema/migration/Dockerfile/.env edits), and `EXECUTION_CONTRACT.md` strictly supersede any generic skill advice.
2. **Mandatory Pre-Implementation Architecture Inspection:** Always inspect `docs/architecture/ADR-0003-open-source-local-first.md`, `START_HERE.md`, and the active task card (`npm run plan -- next`) before modifying code.
3. **Verification Before Completion:** A task is never complete until actual automated tests pass and produce source-bound evidence. Never invent or assume test results.
4. **Simplicity Over Abstraction:** Push for "code judo" moves—deleting unnecessary complexity rather than adding speculative layers or abstractions (`thermo-nuclear-code-quality-review`).
