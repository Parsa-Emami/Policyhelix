# Continue PolicyHelix

Current: local reference workflow verified at C30; full published OSS v1 pending C40.

```sh
npm run setup
npm start
```

Open http://127.0.0.1:4173 and select Reference Workflow. Read docs/engineering/CLONE_TO_RUN.md for actual prerequisites/capability. For implementation read AGENTS.md, docs/agents/EXECUTION_CONTRACT.md and ROADMAP.md, then use:

```sh
npm run validate:plan
npm run plan -- status
npm run plan -- next
```

Each task links exact work/resources/tests. C30 (local usability) is verified by docs/evidence/C30.json; C40 (full OSS v1) requires published-source and installed full-workflow evidence. Do not run historical bootstrap or modify protected files.
