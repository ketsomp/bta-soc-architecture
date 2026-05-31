const fs = require('fs');
const path = require('path');
const { initDb } = require('./src/db');
const { buildApp } = require('./src/app');
const { createLogger, createGraylogUdpTransport } = require('./src/logger');

function loadEnvFile(filename = '.env') {
  const resolvedPath = path.join(process.cwd(), filename);

  if (!fs.existsSync(resolvedPath)) {
    return;
  }

  const contents = fs.readFileSync(resolvedPath, 'utf8');

  contents.split(/\r?\n/).forEach((line) => {
    const normalized = line.trim();

    if (!normalized || normalized.charAt(0) === '#') {
      return;
    }

    const separatorIndex = normalized.indexOf('=');

    if (separatorIndex === -1) {
      return;
    }

    const key = normalized.slice(0, separatorIndex).trim();
    let value = normalized.slice(separatorIndex + 1).trim();

    if (!key || process.env[key] !== undefined) {
      return;
    }

    if (
      (value.charAt(0) === '"' && value.charAt(value.length - 1) === '"') ||
      (value.charAt(0) === "'" && value.charAt(value.length - 1) === "'")
    ) {
      value = value.slice(1, -1);
    }

    process.env[key] = value;
  });
}

function parseBoolean(value) {
  const normalized = String(value || '').trim().toLowerCase();

  return normalized === '1' || normalized === 'true' || normalized === 'yes' || normalized === 'on';
}

function createRuntimeLogger() {
  const host = String(process.env.GRAYLOG_UDP_HOST || '').trim();
  const enabled = process.env.GRAYLOG_UDP_ENABLED
    ? parseBoolean(process.env.GRAYLOG_UDP_ENABLED)
    : Boolean(host);

  return createLogger({
    udpTransport: createGraylogUdpTransport({
      enabled,
      host,
      port: Number(process.env.GRAYLOG_UDP_PORT || 12201),
      family: process.env.GRAYLOG_UDP_FAMILY || 'udp4',
      sourceHost: process.env.GRAYLOG_UDP_SOURCE_HOST || ''
    })
  });
}

loadEnvFile();

async function start() {
  const logEvent = createRuntimeLogger();
  const database = await initDb();
  const app = buildApp({ database, logEvent });
  const port = Number(process.env.PORT || 3000);
  const server = app.listen(port, () => {
    logEvent({
      severity: 'INFO',
      src_ip: '127.0.0.1',
      message: 'server_started',
      port
    });
  });

  const shutdown = async () => {
    app.locals.simulations.stopAll();
    await database.close();
    server.close(() => {
      logEvent.close();
      process.exit(0);
    });
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

start().catch((error) => {
  const logEvent = createRuntimeLogger();
  logEvent({
    severity: 'ERROR',
    src_ip: '127.0.0.1',
    message: 'startup_failed',
    error: error.message
  });
  logEvent.close();
  process.exit(1);
});
