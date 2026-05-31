const crypto = require('crypto');

function createRandomLabel(length) {
  return crypto.randomBytes(Math.ceil(length / 2)).toString('hex').slice(0, length);
}

function wait(durationMs) {
  return new Promise((resolve) => {
    setTimeout(resolve, durationMs);
  });
}

function createMaskedPan(index) {
  return `5412****11${String(index + 10).padStart(2, '0')}`;
}

function createTransactionPayload(context = {}) {
  return Buffer.from(
    JSON.stringify({
      ticket_number: context.ticketNumber,
      terminal_id: context.terminalId,
      fare: context.fare,
      payment_mode: context.paymentMode
    })
  ).toString('hex');
}

function createSimulationManager({
  logEvent,
  dnsIntervalMs = 60000,
  intervalFactory = setInterval,
  clearIntervalFactory = clearInterval,
  sleep = wait,
  randomLabelFactory = createRandomLabel
}) {
  const dnsSessions = new Map();
  const dnsProfiles = new Map();
  const paymentSkimmingProfiles = new Map();
  const gpsProfiles = new Map();

  function emitDnsTunnel({ srcIp, username }) {
    const query = `${randomLabelFactory(100)}.attacker-domain.com`;

    logEvent({
      severity: 'WARNING',
      src_ip: srcIp,
      protocol: 'DNS',
      dest_port: 53,
      query_type: 'TXT',
      query,
      query_length: query.length,
      username
    });
  }

  function armDnsProfile(profile) {
    dnsProfiles.set(profile.terminal_id, profile);
    logEvent({
      severity: 'INFO',
      src_ip: '127.0.0.1',
      message: 'dns_tunneling_armed',
      asset_tag: 'A01',
      terminal_id: profile.terminal_id,
      terminal_site: profile.terminal_site,
      terminal_segment: profile.terminal_segment,
      malicious_domain: profile.malicious_domain,
      query_count: profile.query_count,
      operator_note: profile.operator_note
    });

    return {
      status: 'armed',
      events_on_payment: profile.query_count
    };
  }

  function triggerDnsForPayment({ srcIp, context }) {
    const profile = dnsProfiles.get(context.terminalId);

    if (!profile) {
      return {
        triggered: false
      };
    }

    const payloadPrefix = createTransactionPayload(context);

    for (let index = 0; index < profile.query_count; index += 1) {
      const randomSuffix = randomLabelFactory(Math.max(16, profile.label_length - payloadPrefix.length));
      const queryLabel = `${payloadPrefix}${randomSuffix}`.slice(0, profile.label_length);
      const query = `${queryLabel}.${profile.malicious_domain}`;

      logEvent({
        severity: 'WARNING',
        src_ip: srcIp,
        message: 'dns_tunneling_suspected',
        asset_tag: 'A01',
        terminal_id: profile.terminal_id,
        terminal_site: profile.terminal_site,
        terminal_segment: profile.terminal_segment,
        protocol: 'DNS',
        dest_port: 53,
        query_type: profile.query_type,
        query,
        query_length: query.length,
        malicious_domain: profile.malicious_domain,
        query_sequence: index + 1,
        trigger_source: 'customer_payment',
        ticket_number: context.ticketNumber,
        operator_note: profile.operator_note
      });
    }

    return {
      triggered: true,
      events_emitted: profile.query_count
    };
  }

  function startDnsSession({ sessionId, srcIp, username }) {
    stopDnsSession(sessionId);
    const handle = intervalFactory(() => emitDnsTunnel({ srcIp, username }), dnsIntervalMs);
    dnsSessions.set(sessionId, handle);
  }

  function stopDnsSession(sessionId) {
    const handle = dnsSessions.get(sessionId);

    if (!handle) {
      return;
    }

    clearIntervalFactory(handle);
    dnsSessions.delete(sessionId);
  }

  function stopAll() {
    for (const sessionId of dnsSessions.keys()) {
      stopDnsSession(sessionId);
    }
  }

  function emitAuthSequence({
    srcIp,
    username = 'simulated.user',
    failureCount = 10,
    workstationName = 'BTA-OPS-07',
    sourceLabel = 'ops-console',
    failureReason = 'bad_password',
    successLogonType = 'Interactive',
    correlationKey = 'AUTH-BTA-001',
    operatorNote = 'Manual auth drill from console'
  }) {
    for (let attempt = 0; attempt < failureCount; attempt += 1) {
      logEvent({
        severity: 'WARNING',
        src_ip: srcIp,
        event_id: 4625,
        username,
        status: 'failed',
        attempt_number: attempt + 1,
        workstation_name: workstationName,
        source_label: sourceLabel,
        failure_reason: failureReason,
        correlation_key: correlationKey,
        operator_note: operatorNote
      });
    }

    logEvent({
      severity: 'INFO',
      src_ip: srcIp,
      event_id: 4624,
      username,
      status: 'success',
      workstation_name: workstationName,
      source_label: sourceLabel,
      logon_type: successLogonType,
      correlation_key: correlationKey,
      operator_note: operatorNote
    });

    return {
      events_emitted: failureCount + 1
    };
  }

  async function emitRansomware({
    srcIp,
    assetTag = 'A04',
    operationName = 'BTA central workshop',
    serviceName = 'SysUpdate1',
    encryptedFileCount = 50,
    fileExtension = '.locked',
    targetDirectory = 'C:\\TransitData\\Operations',
    ransomNoteName = 'DECRYPT_FILES.txt',
    destIp = 'malicious_c2_ip',
    destPort = 443,
    fileDelayMs = 80,
    beaconDelayMs = 900,
    encryptionMessage = 'rapid file encryption detected',
    beaconMessage = 'beaconing traffic every 60s'
  }) {
    logEvent({
      severity: 'CRITICAL',
      src_ip: srcIp,
      event_id: 7045,
      service_name: serviceName,
      asset_tag: assetTag,
      operation_name: operationName,
      target_directory: targetDirectory,
      message: 'A new service was installed in the system'
    });

    for (let index = 0; index < encryptedFileCount; index += 1) {
      await sleep(fileDelayMs);
      logEvent({
        severity: 'CRITICAL',
        src_ip: srcIp,
        action: 'file_write',
        asset_tag: assetTag,
        operation_name: operationName,
        target_directory: targetDirectory,
        encrypted_file_index: index + 1,
        file_extension: fileExtension,
        message: encryptionMessage
      });
    }

    logEvent({
      severity: 'CRITICAL',
      src_ip: srcIp,
      action: 'file_create',
      asset_tag: assetTag,
      operation_name: operationName,
      target_directory: targetDirectory,
      file_name: ransomNoteName,
      message: 'ransom note created'
    });

    await sleep(beaconDelayMs);

    logEvent({
      severity: 'CRITICAL',
      src_ip: srcIp,
      mitre_id: 'T1071',
      asset_tag: assetTag,
      operation_name: operationName,
      dest_port: destPort,
      dest_ip: destIp,
      message: beaconMessage
    });

    return {
      events_emitted: encryptedFileCount + 3
    };
  }

  function armPaymentSkimming(profile) {
    logEvent({
      severity: 'CRITICAL',
      src_ip: '127.0.0.1',
      message: 'payment_terminal_tamper',
      asset_tag: 'A01',
      terminal_id: profile.terminal_id,
      terminal_site: profile.terminal_site,
      firmware_version: profile.firmware_version,
      tamper_source: profile.tamper_source,
      integrity_status: 'mismatch',
      cia_impact: 'confidentiality',
      operator_note: profile.operator_note
    });

    paymentSkimmingProfiles.set(profile.terminal_id, profile);

    return {
      status: 'armed',
      events_on_payment: profile.skimmed_card_count + 1
    };
  }

  function triggerPaymentSkimming({ srcIp, context }) {
    const profile = paymentSkimmingProfiles.get(context.terminalId);

    if (!profile) {
      return {
        triggered: false
      };
    }

    for (let index = 0; index < profile.skimmed_card_count; index += 1) {
      logEvent({
        severity: 'CRITICAL',
        src_ip: srcIp,
        message: 'payment_card_read_anomaly',
        asset_tag: 'A01',
        terminal_id: profile.terminal_id,
        terminal_site: profile.terminal_site,
        card_read_index: index + 1,
        masked_pan: createMaskedPan(index),
        tamper_source: profile.tamper_source,
        collection_state: 'tokenization_bypass_suspected',
        trigger_source: 'customer_payment',
        ticket_number: context.ticketNumber,
        operator_note: profile.operator_note
      });
    }

    logEvent({
      severity: 'CRITICAL',
      src_ip: srcIp,
      message: 'payment_data_exfil_attempt',
      asset_tag: 'A01',
      terminal_id: profile.terminal_id,
      terminal_site: profile.terminal_site,
      protocol: 'HTTPS',
      dest_port: 443,
      dest_domain: profile.collector_domain,
      bytes_sent: profile.bytes_sent,
      cia_impact: 'confidentiality',
      trigger_source: 'customer_payment',
      ticket_number: context.ticketNumber,
      operator_note: profile.operator_note
    });

    return {
      triggered: true,
      events_emitted: profile.skimmed_card_count + 1
    };
  }

  function armGpsSpoofing(profile) {
    gpsProfiles.set(profile.bus_number, profile);
    logEvent({
      severity: 'WARNING',
      src_ip: '127.0.0.1',
      message: 'gps_spoofing_armed',
      asset_tag: 'A03',
      bus_number: profile.bus_number,
      route_name: profile.route_name,
      expected_location: profile.expected_location,
      spoofed_location: profile.spoofed_location,
      operator_note: profile.operator_note
    });

    return {
      status: 'armed',
      events_on_lookup: profile.anomaly_count + 1
    };
  }

  function applyGpsSpoofing({ srcIp, buses }) {
    return buses.map((bus) => {
      const profile = gpsProfiles.get(bus.bus_number);

      if (!profile) {
        return {
          ...bus,
          displayed_location: bus.origin_stop,
          route_integrity: 'expected'
        };
      }

      for (let index = 0; index < profile.anomaly_count; index += 1) {
        logEvent({
          severity: 'WARNING',
          src_ip: srcIp,
          message: 'gps_signal_anomaly',
          asset_tag: 'A03',
          bus_number: profile.bus_number,
          route_name: profile.route_name,
          expected_location: profile.expected_location,
          spoofed_location: profile.spoofed_location,
          anomaly_index: index + 1,
          jump_distance_km: profile.jump_distance_km,
          satellite_count: profile.satellite_count,
          cia_impact: 'integrity',
          trigger_source: 'customer_bus_lookup',
          operator_note: profile.operator_note
        });
      }

      logEvent({
        severity: 'ERROR',
        src_ip: srcIp,
        message: 'ghost_bus_projection',
        asset_tag: 'A03',
        bus_number: profile.bus_number,
        route_name: profile.route_name,
        spoofed_location: profile.spoofed_location,
        displayed_stop: profile.displayed_stop,
        schedule_delta_min: profile.schedule_delta_min,
        cia_impact: 'integrity',
        trigger_source: 'customer_bus_lookup',
        operator_note: profile.operator_note
      });

      return {
        ...bus,
        displayed_location: profile.spoofed_location,
        route_integrity: 'spoofed',
        expected_location: profile.expected_location,
        spoofed_location: profile.spoofed_location,
        displayed_stop: profile.displayed_stop,
        schedule_delta_min: profile.schedule_delta_min
      };
    });
  }

  return {
    armDnsProfile,
    triggerDnsForPayment,
    emitAuthSequence,
    emitRansomware,
    armPaymentSkimming,
    triggerPaymentSkimming,
    armGpsSpoofing,
    applyGpsSpoofing,
    startDnsSession,
    stopDnsSession,
    stopAll
  };
}

module.exports = {
  createSimulationManager
};
