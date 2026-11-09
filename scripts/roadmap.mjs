import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve, isAbsolute } from 'node:path';
const root = fileURLToPath(new URL('../', import.meta.url));
const read = async path => JSON.parse(await readFile(resolve(root, path), 'utf8'));
const safe = path => typeof path === 'string' && path.length > 0 && !isAbsolute(path) && !path.split(/[\\/]/).includes('..');
export function validate(plan, progress, requirements, gates) {
  const errors = []; const seen = new Set(); const covered = new Set();
  const states = new Map(progress.commits.map(task => [task.id, task]));
  const ids = Array.from({ length: 40 }, (_, i) => 'C' + String(i + 1).padStart(2, '0'));
  if (JSON.stringify(plan.commits.map(t => t.id)) !== JSON.stringify(ids)) errors.push('Expected ordered C01-C40 tasks.');
  if (JSON.stringify(plan.commits.map(t => t.id)) !== JSON.stringify(progress.commits.map(t => t.id))) errors.push('Progress order mismatch.');
  for (const task of plan.commits) {
    for (const field of ['implementation_steps', 'acceptance', 'deliverables', 'negative_cases', 'read_before', 'verification_commands']) if (!Array.isArray(task[field]) || !task[field].length) errors.push(task.id + ': missing ' + field);
    if (!task.resources?.hardware || !task.resources?.fixture || !task.resources?.upstream?.length || !task.resources?.licenses) errors.push(task.id + ': incomplete resources');
    if (!task.before || !task.after || !task.rollback || !task.stop_conditions?.length) errors.push(task.id + ': incomplete execution boundary');
    if (!/^(feat|fix|docs|chore|test|ci|perf|build|refactor|style|revert)(\([a-z0-9-]+\))?: \S/.test(task.title)) errors.push(task.id + ': invalid commit title');
    if (task.depends_on.some(id => !seen.has(id))) errors.push(task.id + ': forward dependency');
    for (const path of [...task.deliverables, ...task.read_before, task.task_file, task.evidence_path, task.resources?.fixture?.path]) if (!safe(path)) errors.push(task.id + ': unsafe path');
    for (const command of task.verification_commands) if (!command.command || typeof command.available_now !== 'boolean' || !command.expected) errors.push(task.id + ': incomplete command');
    for (const command of task.verification_commands) {
      const introduced = command.introduced_by;
      if (!['web-foundation', 'oss-roadmap'].includes(introduced) && (!ids.includes(introduced) || ids.indexOf(introduced) > ids.indexOf(task.id))) errors.push(task.id + ': command requires a future task');
    }
    for (const id of task.requirements) covered.add(id);
    const state = states.get(task.id);
    if (!state || !['planned', 'in_progress', 'blocked', 'verified'].includes(state.status)) errors.push(task.id + ': invalid progress');
    if (state?.status === 'verified' && (!state.source_identity || !state.evidence?.length || task.depends_on.some(id => states.get(id)?.status !== 'verified'))) errors.push(task.id + ': unproved completion');
    seen.add(task.id);
  }
  const wanted = new Set(requirements.requirements.map(r => r.id));
  if (wanted.size !== requirements.requirements.length || [...wanted].some(id => !covered.has(id)) || [...covered].some(id => !wanted.has(id))) errors.push('Requirement coverage mismatch');
  for (const req of requirements.requirements) if (plan.commits.find(task => task.requirements.includes(req.id))?.id !== req.planned_commit) errors.push(req.id + ': wrong requirement owner');
  if (gates.usable_at !== 'C30' || gates.oss_v1_at !== 'C40' || typeof gates.core_ready !== 'boolean') errors.push('Missing explicit release gates');
  if (gates.core_ready && progress.commits.slice(0, 30).some(t => t.status !== 'verified')) errors.push('Core readiness requires C01-C30 proof');
  return errors;
}
export async function load() {
  const [plan, progress, requirements, gates, web] = await Promise.all(['plans/roadmap.json', 'plans/progress.json', 'plans/requirements.json', 'plans/release-gates.json', 'plans/web-roadmap.json'].map(read));
  const errors = validate(plan, progress, requirements, gates);
  for (const task of plan.commits) {
    for (const path of [...task.read_before, task.task_file]) try { await readFile(resolve(root, path)); } catch { errors.push(task.id + ': missing ' + path); }
    const state = progress.commits.find(t => t.id === task.id);
    if (state.status === 'verified') for (const path of state.evidence) {
      if (!safe(path)) { errors.push(task.id + ': unsafe evidence'); continue; }
      try { const proof = await read(path); if (!proof.passed || proof.planning_template || proof.commit_id !== task.id || proof.source_identity !== state.source_identity || !proof.commands?.length || proof.commands.some(c => c.exit_code !== 0)) errors.push(task.id + ': invalid evidence'); } catch { errors.push(task.id + ': missing evidence'); }
    }
  }
  if (web.tasks.length !== 8 || web.project !== plan.project) errors.push('Web task identity mismatch');
  for (const task of web.tasks) if (task.status === 'verified') for (const path of task.evidence ?? []) {
    if (!safe(path)) { errors.push('Unsafe web evidence'); continue; }
    try { const proof = await read(path); if (!proof.passed || !proof.web_tasks_verified?.includes(task.id)) errors.push(task.id + ': invalid historical web proof'); } catch { errors.push(task.id + ': missing web proof'); }
  }
  return { plan, progress, gates, errors };
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) try {
  const command = process.argv[2] ?? 'status';
  const { plan, progress, gates, errors } = await load();
  if (command === 'release-check') {
    const requiredPrereqs = gates.release_prerequisites ?? Array.from({ length: 38 }, (_, i) => 'C' + String(i + 1).padStart(2, '0'));
    const missing = requiredPrereqs.filter(id => progress.commits.find(t => t.id === id)?.status !== 'verified');
    const gateErrors = [...errors];
    if (missing.length) gateErrors.push('Missing verified prerequisite tasks: ' + missing.join(', '));
    if (!gates.core_ready) gateErrors.push('Core readiness not certified in plans/release-gates.json (core_ready must be true)');
    for (const id of ['C30', 'C35', 'C36', 'C38']) {
      const taskState = progress.commits.find(t => t.id === id);
      if (!taskState || taskState.status !== 'verified') {
        gateErrors.push(`Required milestone ${id} is not verified`);
      }
    }
    const requiredReleaseAssets = [
      'LICENSE',
      'NOTICE',
      'THIRD_PARTY_NOTICES.md',
      'docs/release/SERVICE_POLICY.md',
      'docs/release/MAINTENANCE.md',
      'docs/release/USER_GUIDE.md',
      'docs/release/ARTIFACTS.md',
      'docs/product/ONBOARDING_RESULTS.md'
    ];
    for (const asset of requiredReleaseAssets) {
      try {
        await readFile(resolve(root, asset));
      } catch {
        gateErrors.push(`Required release asset missing: ${asset}`);
      }
    }
    const milestoneProofs = [
      'docs/evidence/C30.json',
      'docs/evidence/C35.json',
      'docs/evidence/C36.json',
      'docs/evidence/C38.json'
    ];
    for (const proofPath of milestoneProofs) {
      try {
        const proof = await read(proofPath);
        if (!proof.passed || proof.planning_template) {
          gateErrors.push(`${proofPath}: milestone evidence must have passed: true and planning_template: false`);
        }
      } catch (err) {
        gateErrors.push(`Missing or unreadable milestone evidence ${proofPath}: ${err.message}`);
      }
    }
    try {
      const v1Gate = await read('docs/evidence/v1-gate.json');
      if (v1Gate.commit_id !== 'C39' || v1Gate.requirement !== 'N39') {
        gateErrors.push('docs/evidence/v1-gate.json: commit_id must be C39 and requirement must be N39');
      }
      if (!v1Gate.passed || v1Gate.planning_template || !v1Gate.core_ready) {
        gateErrors.push('docs/evidence/v1-gate.json: gate proof must have passed: true, core_ready: true, and planning_template: false');
      }
      if (!v1Gate.release_gates?.core_ready || !v1Gate.release_gates?.local_usable_verified || !v1Gate.release_gates?.clone_to_value_verified || !v1Gate.release_gates?.signed_packaging_verified || !v1Gate.release_gates?.service_policy_verified) {
        gateErrors.push('docs/evidence/v1-gate.json: release_gates verification incomplete');
      }
      if (v1Gate.clone_to_value?.status !== 'verified') {
        gateErrors.push('docs/evidence/v1-gate.json: clone_to_value status must be verified');
      }
      if (v1Gate.packaging_and_integrity?.status !== 'verified') {
        gateErrors.push('docs/evidence/v1-gate.json: packaging_and_integrity status must be verified');
      }
      if (v1Gate.service_policy_and_maintenance?.status !== 'verified') {
        gateErrors.push('docs/evidence/v1-gate.json: service_policy_and_maintenance status must be verified');
      }
      if (v1Gate.licensing_governance?.status !== 'verified') {
        gateErrors.push('docs/evidence/v1-gate.json: licensing_governance status must be verified');
      }
      if (!v1Gate.security_and_recovery?.writer_crash_recovery?.verified ||
          !v1Gate.security_and_recovery?.operation_replay_deduplication?.verified ||
          !v1Gate.security_and_recovery?.quota_and_resource_limits?.verified ||
          !v1Gate.security_and_recovery?.private_resources_fail_closed?.verified) {
        gateErrors.push('docs/evidence/v1-gate.json: security_and_recovery controls must be verified');
      }
    } catch (err) {
      gateErrors.push(`docs/evidence/v1-gate.json: missing or unreadable release gate certification (${err.message})`);
    }
    if (gateErrors.length) {
      console.error('RELEASE GATE CHECK FAILED:\n' + gateErrors.map(e => ' - ' + e).join('\n'));
      process.exitCode = 2;
    } else {
      console.log('RELEASE GATE PASSED: C01-C38 verified, core readiness certified, and open-source v1 release prerequisites met.');
      process.exitCode = 0;
    }
  } else {
    if (errors.length) throw new Error(errors.join('\n'));
    if (command === 'validate') console.log('Validated 40 detailed tasks, resources, references and progress; no runtime capability inferred.');
    else if (command === 'status') console.log(JSON.stringify({ project: plan.project, readiness: progress.readiness, verified: progress.commits.filter(t => t.status === 'verified').length, total: 40, core_ready: gates.core_ready, usable_at: 'C30', oss_v1_at: 'C40' }, null, 2));
    else if (command === 'show' || command === 'next') {
      const states = new Map(progress.commits.map(t => [t.id, t]));
      const task = command === 'show' ? plan.commits.find(t => t.id === process.argv[3]) : plan.commits.find(t => states.get(t.id).status !== 'verified' && t.depends_on.every(id => states.get(id).status === 'verified'));
      if (!task) throw new Error('No matching/dependency-ready task; inspect blockers.');
      console.log(JSON.stringify({ task, progress: states.get(task.id) }, null, 2));
    } else throw new Error('Usage: npm run plan -- [validate|status|next|show C07|release-check]');
  }
} catch (error) {
  console.error(error.message);
  process.exitCode = (process.argv[2] === 'release-check') ? 2 : 1;
}
