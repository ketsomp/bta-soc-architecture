const dgram = require('dgram');
const os = require('os');

const DEFAULT_MITRE_ID = 'N/A';
const MITRE_ID_BY_EVENT_ID = {
  4624: 'T1078',
  4625: 'T1110',
  7045: 'T1543.003'
};
const MITRE_ID_BY_ACTION = {
  file_create: 'T1486',
  file_write: 'T1486'
};
const MITRE_ID_BY_MESSAGE = {
  dns_tunneling_armed: 'T1071.004',
  dns_tunneling_suspected: 'T1071.004',
  payment_terminal_tamper: 'T1056',
  payment_card_read_anomaly: 'T1056',
  payment_data_exfil_attempt: 'T1041',
  gps_spoofing_armed: 'T1565.002',
  gps_signal_anomaly: 'T1565.002',
  ghost_bus_projection: 'T1565.003'
};

function severityToGelfLevel(severity) {
  if (severity === 'CRITICAL') {
    return 2;
  }

  if (severity === 'ERROR') {
    return 3;
  }

  if (severity === 'WARNING') {
    return 4;
  }

  return 6;
}

function normalizeTransportValue(value) {
  if (value === undefined || value === null) {
    return null;
  }

  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    return value;
  }

  return JSON.stringify(value);
}

function buildShortMessage(record) {
  if (typeof record.message === 'string' && record.message.trim()) {
    return record.message;
  }

  if (record.event_id !== undefined && record.event_id !== null) {
    return `event_id:${record.event_id}`;
  }

  if (typeof record.action === 'string' && record.action.trim()) {
    return `action:${record.action}`;
  }

  return 'bta-fms';
}

function normalizeMitreId(value) {
  const normalized = String(value == null ? '' : value).trim();

  return normalized || null;
}

function deriveMitreId(record) {
  const explicitMitreId = normalizeMitreId(record.mitre_id);

  if (explicitMitreId) {
    return explicitMitreId;
  }

  if (
    record.event_id !== undefined &&
    record.event_id !== null &&
    MITRE_ID_BY_EVENT_ID[record.event_id]
  ) {
    return MITRE_ID_BY_EVENT_ID[record.event_id];
  }

  if (typeof record.action === 'string' && MITRE_ID_BY_ACTION[record.action]) {
    return MITRE_ID_BY_ACTION[record.action];
  }

  if (typeof record.message === 'string' && MITRE_ID_BY_MESSAGE[record.message]) {
    return MITRE_ID_BY_MESSAGE[record.message];
  }

  if (record.protocol === 'DNS') {
    return 'T1071.004';
  }

  return DEFAULT_MITRE_ID;
}

function createGraylogUdpTransport({
  enabled = false,
  host = '',
  port = 12201,
  family = 'udp4',
  sourceHost = '',
  socket = null
} = {}) {
  const destinationHost = String(host || '').trim();
  const destinationPort = Number(port || 0);

  if (!enabled || !destinationHost || !destinationPort) {
    const noopTransport = function noopTransport() {};
    noopTransport.close = function close() {};
    return noopTransport;
  }

  const udpSocket = socket || dgram.createSocket(family === 'udp6' ? 'udp6' : 'udp4');
  const gelfHost = String(sourceHost || process.env.HOSTNAME || os.hostname() || 'bta-fms').trim();

  if (udpSocket && typeof udpSocket.on === 'function') {
    udpSocket.on('error', function onError() {});
  }

  const transport = function transport(record) {
    const timestampMs = Date.parse(record.timestamp);
    const gelfRecord = {
      version: '1.1',
      host: gelfHost,
      short_message: buildShortMessage(record),
      full_message: JSON.stringify(record),
      timestamp: Number.isFinite(timestampMs) ? timestampMs / 1000 : Date.now() / 1000,
      level: severityToGelfLevel(record.severity),
      facility: record.app_name || 'bta-fms'
    };

    Object.keys(record).forEach((key) => {
      const value = normalizeTransportValue(record[key]);

      if (value === null) {
        return;
      }

      gelfRecord[`_${key}`] = value;
    });

    gelfRecord._transport = 'udp';

    const buffer = Buffer.from(JSON.stringify(gelfRecord));

    udpSocket.send(buffer, 0, buffer.length, destinationPort, destinationHost, function onSend() {});
  };

  transport.close = function close() {
    if (udpSocket && typeof udpSocket.close === 'function') {
      try {
        udpSocket.close();
      } catch (error) {}
    }
  };

  return transport;
}

function createLogger({ sink = process.stdout, udpTransport = null } = {}) {
  const transport = typeof udpTransport === 'function' ? udpTransport : null;

  const logEvent = function logEvent(event = {}) {
    const { src_ip, severity, ...payload } = event;
    const baseRecord = {
      ...payload
    };
    const record = {
      timestamp: new Date().toISOString(),
      app_name: 'bta-fms',
      src_ip: src_ip || '127.0.0.1',
      severity: severity || 'INFO',
      ...baseRecord,
      mitre_id: deriveMitreId(baseRecord)
    };

    sink.write(`${JSON.stringify(record)}\n`);

    if (transport) {
      try {
        transport(record);
      } catch (error) {}
    }

    return record;
  };

  logEvent.close = function close() {
    if (transport && typeof transport.close === 'function') {
      transport.close();
    }
  };

  return logEvent;
}

function getSourceIp(req) {
  const forwarded = req.headers['x-forwarded-for'];

  if (typeof forwarded === 'string' && forwarded.trim()) {
    return forwarded.split(',')[0].trim();
  }

  return req.socket && req.socket.remoteAddress ? req.socket.remoteAddress : '127.0.0.1';
}

function isLocalhost(ipAddress) {
  return ipAddress === '127.0.0.1' || ipAddress === '::1' || ipAddress === '::ffff:127.0.0.1';
}

module.exports = {
  createLogger,
  createGraylogUdpTransport,
  getSourceIp,
  isLocalhost
};
