import { spawn } from 'node:child_process';
import { readFile, stat } from 'node:fs/promises';
import net from 'node:net';
import { resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createWebServer } from './serve-web.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));

export function checkPortAvailable(port, host = '127.0.0.1') {
  return new Promise((res, rej) => {
    const s = net.createServer();
    s.once('error', err => {
      if (err.code === 'EADDRINUSE') {
        rej(new Error(`Port ${port} is already in use on ${host}`));
      } else {
        rej(err);
      }
    });
    s.once('listening', () => {
      s.close(() => res(true));
    });
    s.listen(port, host);
  });
}

export async function waitForEngineHealth(url, timeoutMs = 5000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const resp = await fetch(`${url}/healthz`, { signal: AbortSignal.timeout(1000) });
      if (resp.ok) {
        const body = await resp.json();
        if (body.status === 'ok') return body;
      }
    } catch {}
    await new Promise(r => setTimeout(r, 100));
  }
  throw new Error(`Engine failed to become healthy at ${url}/healthz within ${timeoutMs}ms`);
}

export async function startSupervisor(options = {}) {
  const host = options.host ?? '127.0.0.1';
  const port = Number(options.port ?? 4173);
  const enginePort = Number(options.enginePort ?? 4174);
  const webRoot = resolve(root, options.root ?? 'dist/web');
  const configPath = resolve(root, options.config ?? 'ops/web/runtime-config.json');
  const engineBinPath = resolve(root, options.engineBin ?? 'dist/engine/policyhelix');

  if (!['127.0.0.1', '::1', 'localhost'].includes(host)) {
    throw new Error(`Fail closed: supervisor must bind to loopback (127.0.0.1 or ::1), received '${host}'`);
  }

  // Verify prerequisites exist
  try {
    await stat(resolve(webRoot, 'index.html'));
  } catch {
    throw new Error('Web assets missing in ' + webRoot + '. Run npm run setup first.');
  }

  try {
    await stat(engineBinPath);
  } catch {
    throw new Error('Engine binary missing at ' + engineBinPath + '. Run npm run setup first.');
  }

  // Pre-check ports
  await checkPortAvailable(port, host);
  await checkPortAvailable(enginePort, host);

  const product = JSON.parse(await readFile(resolve(root, 'ops/web/brand.json'), 'utf8'));
  const config = JSON.parse(await readFile(configPath, 'utf8'));

  let stopping = false;
  const storageDir = resolve(root, options.storageDir ?? (enginePort === 4174 ? '.local-data/storage' : `.local-data/storage-${enginePort}`));

  // Spawn Go engine
  const engineProcess = spawn(engineBinPath, [
    '--host', host,
    '--port', String(enginePort),
    '--storage-dir', storageDir,
  ], {
    cwd: root,
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  let engineExitedUnexpectedly = false;
  const exitPromise = new Promise((_, rej) => {
    engineProcess.once('exit', (code, sig) => {
      if (!stopping) {
        engineExitedUnexpectedly = true;
        rej(new Error(`Engine process exited unexpectedly (code: ${code}, signal: ${sig})`));
      }
    });
  });

  const engineUrl = `http://${host}:${enginePort}`;

  // Race health check against premature engine exit
  let engineHealth;
  try {
    engineHealth = await Promise.race([
      waitForEngineHealth(engineUrl, 5000),
      exitPromise,
    ]);
  } catch (err) {
    if (engineProcess.exitCode === null && engineProcess.pid) {
      engineProcess.kill('SIGKILL');
    }
    throw err;
  }

  // Start web server
  const server = createWebServer({
    root: webRoot,
    config,
    projectId: product.slug,
    engineUrl,
  });

  server.maxRequestsPerSocket = 1000;

  await new Promise((resolveListening, rejectListening) => {
    server.once('error', rejectListening);
    server.listen(port, host, () => resolveListening());
  });

  async function stop() {
    if (stopping) return;
    stopping = true;

    // 1. Close web server
    await new Promise(r => {
      server.close(() => r());
      server.closeAllConnections();
    });

    // 2. Gracefully signal engine
    if (engineProcess.exitCode === null && engineProcess.pid) {
      engineProcess.kill('SIGTERM');
      const termTimer = setTimeout(() => {
        try {
          if (engineProcess.exitCode === null) engineProcess.kill('SIGKILL');
        } catch {}
      }, 4000);

      await new Promise(r => engineProcess.once('exit', r));
      clearTimeout(termTimer);
    }
  }

  engineProcess.on('exit', () => {
    if (!stopping) {
      void stop();
    }
  });

  return {
    host,
    port,
    enginePort,
    storageDir,
    engineUrl,
    engineHealth,
    engineProcess,
    server,
    stop,
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const args = process.argv.slice(2);
    const options = { host: '127.0.0.1', port: '4173', enginePort: '4174', root: 'dist/web', config: 'ops/web/runtime-config.json', engineBin: 'dist/engine/policyhelix', storageDir: undefined };
    for (let i = 0; i < args.length; i += 2) {
      const key = args[i].startsWith('--') ? args[i].slice(2).replace(/-([a-z])/g, (_, letter) => letter.toUpperCase()) : '';
      if (!key || !Object.hasOwn(options, key) || !args[i + 1]) {
        throw new Error('Usage: node scripts/start-local.mjs [--host 127.0.0.1] [--port 4173] [--engine-port 4174] [--root dist/web] [--config path] [--engine-bin path] [--storage-dir path]');
      }
      options[key] = args[i + 1];
    }

    const supervisor = await startSupervisor(options);
    console.log(JSON.stringify({
      service: 'policyhelix-unified-supervisor',
      host: supervisor.host,
      port: supervisor.port,
      enginePort: supervisor.enginePort,
      engine: supervisor.engineHealth?.engine,
      version: supervisor.engineHealth?.version,
      engineReady: true,
      referenceWorkflow: true,
      storageDir: supervisor.storageDir,
      note: 'Supervising the web workspace, loopback Go engine, durable local storage and the owned synthetic upstream',
    }));

    for (const signal of ['SIGINT', 'SIGTERM']) {
      process.once(signal, async () => {
        await supervisor.stop();
        process.exit(0);
      });
    }
  } catch (err) {
    console.error('Supervisor startup failed: ' + err.message);
    process.exitCode = 1;
  }
}
