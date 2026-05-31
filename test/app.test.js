const test = require('node:test');
const assert = require('node:assert/strict');
const EventEmitter = require('node:events');
const { initDb } = require('../src/db');
const { createLogger, createGraylogUdpTransport } = require('../src/logger');
const { createSimulationManager } = require('../src/simulations');
const { createAccessLogMiddleware, createControllers } = require('../src/app');

function createSession(initial = {}) {
  return {
    id: initial.id || 'session-1',
    user: initial.user || null,
    saved: false,
    destroyed: false,
    save(callback) {
      this.saved = true;
      callback(null);
    },
    destroy(callback) {
      this.destroyed = true;
      this.user = null;
      callback(null);
    }
  };
}

function createRequest({
  method = 'GET',
  originalUrl = '/',
  body = {},
  query = {},
  headers = {},
  session = createSession(),
  srcIp = '127.0.0.1'
} = {}) {
  const normalizedHeaders = {};

  for (const [name, value] of Object.entries(headers)) {
    normalizedHeaders[name.toLowerCase()] = value;
  }

  return {
    method,
    originalUrl,
    url: originalUrl,
    body,
    query,
    headers: normalizedHeaders,
    session,
    socket: {
      remoteAddress: srcIp
    },
    get(name) {
      return normalizedHeaders[name.toLowerCase()];
    }
  };
}

function createResponse() {
  const response = new EventEmitter();
  response.statusCode = 200;
  response.headersSent = false;
  response.locals = {};
  response.clearedCookies = [];
  response.status = function status(code) {
    this.statusCode = code;
    return this;
  };
  response.render = function render(view, payload) {
    this.headersSent = true;
    this.view = view;
    this.rendered = payload;
    this.emit('finish');
    return this;
  };
  response.redirect = function redirect(location) {
    this.headersSent = true;
    if (this.statusCode === 200) {
      this.statusCode = 302;
    }
    this.redirectLocation = location;
    this.emit('finish');
    return this;
  };
  response.json = function json(payload) {
    this.headersSent = true;
    this.jsonBody = payload;
    this.emit('finish');
    return this;
  };
  response.clearCookie = function clearCookie(name) {
    this.clearedCookies.push(name);
    return this;
  };
  return response;
}

async function invoke(handler, req, res) {
  let nextCalled = false;
  let nextError;

  await handler(req, res, (error) => {
    nextCalled = true;
    nextError = error;
  });

  if (nextError) {
    throw nextError;
  }

  return { nextCalled };
}

async function createHarness(simulationOptions = {}) {
  const records = [];
  const database = await initDb({ filename: ':memory:' });
  const logEvent = createLogger({
    sink: {
      write(line) {
        records.push(JSON.parse(line));
      }
    }
  });
  const simulations = createSimulationManager({
    logEvent,
    intervalFactory: () => ({ active: true }),
    clearIntervalFactory: () => {},
    ...simulationOptions
  });
  const controllers = createControllers({
    database,
    logEvent,
    simulations,
    simulationSecret: 'simulate-bta'
  });
  const accessLogMiddleware = createAccessLogMiddleware(logEvent);

  return {
    controllers,
    accessLogMiddleware,
    records,
    simulations,
    async close() {
      simulations.stopAll();
      await database.close();
    }
  };
}

test('logger writes stdout JSON and Graylog GELF over UDP when transport is enabled', () => {
  const records = [];
  const sentPackets = [];
  const socket = {
    closed: false,
    on() {},
    send(buffer, offset, length, port, host, callback) {
      sentPackets.push({
        payload: JSON.parse(buffer.toString('utf8', offset, offset + length)),
        port,
        host
      });

      if (typeof callback === 'function') {
        callback(null);
      }
    },
    close() {
      this.closed = true;
    }
  };
  const logEvent = createLogger({
    sink: {
      write(line) {
        records.push(JSON.parse(line));
      }
    },
    udpTransport: createGraylogUdpTransport({
      enabled: true,
      host: '127.0.0.1',
      port: 12201,
      sourceHost: 'bta-fms-web',
      socket
    })
  });

  const record = logEvent({
    severity: 'WARNING',
    src_ip: '10.10.4.25',
    message: 'dns_tunneling_suspected',
    terminal_id: 'A01-PAY-014',
    query_length: 120
  });

  assert.equal(records.length, 1);
  assert.equal(records[0].message, 'dns_tunneling_suspected');
  assert.equal(records[0].terminal_id, 'A01-PAY-014');
  assert.equal(records[0].mitre_id, 'T1071.004');

  assert.equal(sentPackets.length, 1);
  assert.equal(sentPackets[0].host, '127.0.0.1');
  assert.equal(sentPackets[0].port, 12201);
  assert.equal(sentPackets[0].payload.version, '1.1');
  assert.equal(sentPackets[0].payload.host, 'bta-fms-web');
  assert.equal(sentPackets[0].payload.short_message, 'dns_tunneling_suspected');
  assert.equal(sentPackets[0].payload.facility, 'bta-fms');
  assert.equal(sentPackets[0].payload._app_name, 'bta-fms');
  assert.equal(sentPackets[0].payload._severity, 'WARNING');
  assert.equal(sentPackets[0].payload._src_ip, '10.10.4.25');
  assert.equal(sentPackets[0].payload._terminal_id, 'A01-PAY-014');
  assert.equal(sentPackets[0].payload._query_length, 120);
  assert.equal(sentPackets[0].payload._mitre_id, 'T1071.004');
  assert.equal(sentPackets[0].payload._transport, 'udp');
  assert.equal(sentPackets[0].payload._message, record.message);

  logEvent.close();
  assert.equal(socket.closed, true);
});

test('login failure and role-based redirects emit auth logs and enforce dashboard access', async () => {
  const harness = await createHarness();

  const blockedRequest = createRequest({
    method: 'GET',
    originalUrl: '/dashboard'
  });
  const blockedResponse = createResponse();
  await invoke(harness.controllers.requireAuth, blockedRequest, blockedResponse);
  assert.equal(blockedResponse.redirectLocation, '/login');

  const failedRequest = createRequest({
    method: 'POST',
    originalUrl: '/login',
    body: {
      username: 'admin',
      password: 'wrong-pass'
    }
  });
  const failedResponse = createResponse();
  await invoke(harness.controllers.postLogin, failedRequest, failedResponse);

  const failedLog = harness.records.find((record) => record.event_id === 4625);
  assert.ok(failedLog);
  assert.equal(failedLog.username, 'admin');
  assert.equal(failedResponse.statusCode, 401);
  assert.equal(failedResponse.view, 'login');

  const adminSession = createSession({ id: 'session-admin' });
  const adminRequest = createRequest({
    method: 'POST',
    originalUrl: '/login',
    body: {
      username: 'admin',
      password: 'transit123'
    },
    session: adminSession
  });
  const adminResponse = createResponse();
  await invoke(harness.controllers.postLogin, adminRequest, adminResponse);
  assert.equal(adminRequest.session.user.role, 'admin');
  assert.equal(adminResponse.redirectLocation, '/admin/dashboard');

  const customerSession = createSession({ id: 'session-customer' });
  const customerRequest = createRequest({
    method: 'POST',
    originalUrl: '/login',
    body: {
      username: 'customer',
      password: 'ride123'
    },
    session: customerSession
  });
  const customerResponse = createResponse();
  await invoke(harness.controllers.postLogin, customerRequest, customerResponse);
  assert.equal(customerRequest.session.user.role, 'customer');
  assert.equal(customerResponse.redirectLocation, '/customer/dashboard');

  const adminDashboardRequest = createRequest({
    method: 'GET',
    originalUrl: '/dashboard',
    session: adminSession
  });
  const adminDashboardResponse = createResponse();
  await invoke(harness.controllers.getDashboard, adminDashboardRequest, adminDashboardResponse);
  assert.equal(adminDashboardResponse.redirectLocation, '/admin/dashboard');

  const customerGuardResponse = createResponse();
  await invoke(harness.controllers.requireCustomer, customerRequest, customerGuardResponse);
  assert.equal(customerGuardResponse.headersSent, false);

  const rejectedAdminOnCustomerPage = createResponse();
  await invoke(harness.controllers.requireCustomer, adminRequest, rejectedAdminOnCustomerPage);
  assert.equal(rejectedAdminOnCustomerPage.redirectLocation, '/admin/dashboard');

  const logoutResponse = createResponse();
  await invoke(harness.controllers.postLogout, adminRequest, logoutResponse);
  assert.equal(adminRequest.session.destroyed, true);
  assert.equal(logoutResponse.redirectLocation, '/login');

  await harness.close();
});

test('admin ticket query returns filtered data and emits query logs', async () => {
  const harness = await createHarness();
  const request = createRequest({
    method: 'GET',
    originalUrl:
      '/api/passenger/tickets?route_name=Majestic&status=issued&bus_number=KA-01-FM&limit=1&operator_label=shift-audit',
    query: {
      route_name: 'Majestic',
      status: 'issued',
      bus_number: 'KA-01-FM',
      limit: '1',
      operator_label: 'shift-audit'
    },
    session: createSession({
      user: {
        id: 1,
        username: 'admin',
        role: 'admin'
      }
    })
  });
  const response = createResponse();

  const accessResult = await invoke(harness.accessLogMiddleware, request, response);
  assert.equal(accessResult.nextCalled, true);
  await invoke(harness.controllers.getPassengerTickets, request, response);

  assert.equal(response.jsonBody.total, 1);
  assert.equal(response.jsonBody.tickets[0].ticket_number, 'BTA-24001');
  assert.equal(response.jsonBody.tickets[0].bus_number, 'KA-01-FM-1142');

  const queryLog = harness.records.find((record) => record.message === 'ticket_console_query');
  const accessLog = harness.records.find((record) => record.message === 'http_access');
  assert.ok(queryLog);
  assert.ok(accessLog);
  assert.equal(queryLog.route_name_filter, 'Majestic');
  assert.equal(queryLog.bus_number_filter, 'KA-01-FM');
  assert.equal(queryLog.operator_label, 'shift-audit');
  assert.equal(queryLog.mitre_id, 'N/A');
  assert.equal(accessLog.mitre_id, 'N/A');

  await harness.close();
});

test('customer booking creates a ticket and emits a booking log', async () => {
  const harness = await createHarness();
  const session = createSession({
    id: 'session-customer',
    user: {
      id: 3,
      username: 'customer',
      role: 'customer'
    }
  });
  const request = createRequest({
    method: 'POST',
    originalUrl: '/api/customer/bookings',
    body: {
      passenger_name: 'Customer Rider',
      passenger_contact: '9999900000',
      route_name: 'Majestic - Whitefield',
      source_stop: 'Majestic',
      destination_stop: 'Whitefield',
      travel_date: '2026-04-06T10:00',
      bus_number: 'KA-01-FM-1142',
      seat_number: '14B',
      payment_mode: 'Card',
      booking_channel: 'kiosk',
      payment_terminal_id: 'A01-PAY-014',
      fare: '45',
      operator_label: 'customer-web-booking',
      travel_note: 'test journey'
    },
    session
  });
  const response = createResponse();

  await invoke(harness.controllers.postCustomerBooking, request, response);

  assert.equal(response.statusCode, 201);
  assert.equal(response.jsonBody.booking.status, 'booked');
  assert.equal(response.jsonBody.booking.passenger_name, 'Customer Rider');
  assert.equal(response.jsonBody.booking.payment_terminal_id, 'A01-PAY-014');
  assert.match(response.jsonBody.booking.ticket_number, /^BTA-/);
  assert.equal(response.jsonBody.scenario_signals.payment_skimming.triggered, false);
  assert.equal(response.jsonBody.scenario_signals.dns_tunneling.triggered, false);

  const bookingLog = harness.records.find((record) => record.message === 'customer_ticket_booking');
  assert.ok(bookingLog);
  assert.equal(bookingLog.passenger_name, 'Customer Rider');
  assert.equal(bookingLog.seat_number, '14B');
  assert.equal(bookingLog.payment_mode, 'Card');
  assert.equal(bookingLog.payment_terminal_id, 'A01-PAY-014');
  assert.equal(bookingLog.mitre_id, 'N/A');

  await harness.close();
});

test('customer bus lookup returns fleet data and emits search logs', async () => {
  const harness = await createHarness();
  const request = createRequest({
    method: 'GET',
    originalUrl: '/api/customer/buses?route_name=Majestic&vehicle_status=in_service&limit=5',
    query: {
      route_name: 'Majestic',
      vehicle_status: 'in_service',
      limit: '5',
      operator_label: 'customer-bus-refresh'
    },
    session: createSession({
      user: {
        id: 3,
        username: 'customer',
        role: 'customer'
      }
    })
  });
  const response = createResponse();

  await invoke(harness.controllers.getCustomerBuses, request, response);

  assert.equal(response.jsonBody.total, 1);
  assert.equal(response.jsonBody.buses[0].bus_number, 'KA-01-FM-1142');
  assert.equal(response.jsonBody.buses[0].route_integrity, 'expected');
  assert.equal(response.jsonBody.scenario_summary.spoofed_count, 0);

  const busLog = harness.records.find((record) => record.message === 'customer_bus_lookup');
  assert.ok(busLog);
  assert.equal(busLog.route_name_filter, 'Majestic');
  assert.equal(busLog.vehicle_status_filter, 'in_service');
  assert.equal(busLog.spoofed_result_count, 0);

  await harness.close();
});

test('customer ticket status lookup returns matching tickets and emits status logs', async () => {
  const harness = await createHarness();
  const request = createRequest({
    method: 'GET',
    originalUrl:
      '/api/customer/ticket-status?ticket_number=BTA-24001&passenger_name=Ananya&status=issued',
    query: {
      ticket_number: 'BTA-24001',
      passenger_name: 'Ananya',
      status: 'issued',
      operator_label: 'customer-status-check'
    },
    session: createSession({
      user: {
        id: 3,
        username: 'customer',
        role: 'customer'
      }
    })
  });
  const response = createResponse();

  await invoke(harness.controllers.getCustomerTicketStatus, request, response);

  assert.equal(response.jsonBody.total, 1);
  assert.equal(response.jsonBody.tickets[0].ticket_number, 'BTA-24001');
  assert.equal(response.jsonBody.tickets[0].status, 'issued');

  const statusLog = harness.records.find((record) => record.message === 'customer_ticket_status_lookup');
  assert.ok(statusLog);
  assert.equal(statusLog.ticket_number_filter, 'BTA-24001');
  assert.equal(statusLog.status_filter, 'issued');

  await harness.close();
});

test('simulation guard allows localhost requests and auth sequence emits the expected event pattern', async () => {
  const harness = await createHarness();
  const request = createRequest({
    method: 'POST',
    originalUrl: '/api/simulations/auth-sequence',
    body: {
      username: 'svc.transit.sync',
      failure_count: '12',
      workstation_name: 'BTA-OPS-11',
      source_label: 'night-shift-console',
      failure_reason: 'locked_account',
      success_logon_type: 'RemoteInteractive',
      correlation_key: 'AUTH-BTA-077',
      operator_note: 'night shift auth drill'
    }
  });
  const guardResponse = createResponse();

  const guardResult = await invoke(harness.controllers.requireSimulationAccess, request, guardResponse);
  assert.equal(guardResult.nextCalled, true);

  const response = createResponse();
  await invoke(harness.controllers.postAuthSequence, request, response);

  const failedEvents = harness.records.filter(
    (record) => record.event_id === 4625 && record.status === 'failed'
  );
  const successEvents = harness.records.filter(
    (record) => record.event_id === 4624 && record.status === 'success'
  );

  assert.equal(response.statusCode, 202);
  assert.equal(response.jsonBody.events_emitted, 13);
  assert.equal(response.jsonBody.config.workstation_name, 'BTA-OPS-11');
  assert.equal(failedEvents.length, 12);
  assert.equal(successEvents.length, 1);
  assert.equal(failedEvents[0].workstation_name, 'BTA-OPS-11');
  assert.equal(failedEvents[0].correlation_key, 'AUTH-BTA-077');
  assert.equal(failedEvents[0].mitre_id, 'T1110');
  assert.equal(successEvents[0].logon_type, 'RemoteInteractive');
  assert.equal(successEvents[0].mitre_id, 'T1078');

  await harness.close();
});

test('dns tunneling can be armed by admin and triggered by a matching customer payment', async () => {
  const harness = await createHarness({
    sleep: async () => {}
  });
  const armRequest = createRequest({
    method: 'POST',
    originalUrl: '/api/simulations/dns-tunneling',
    body: {
      terminal_id: 'A01-PAY-014',
      terminal_site: 'Majestic Gate 2',
      terminal_segment: 'payment-vlan',
      malicious_domain: 'collector.attacker-domain.com',
      query_count: '4',
      label_length: '110',
      query_type: 'TXT',
      query_interval_ms: '5',
      operator_note: 'dns exfil drill'
    }
  });
  const armResponse = createResponse();

  await invoke(harness.controllers.postDnsTunneling, armRequest, armResponse);

  assert.equal(armResponse.statusCode, 202);
  assert.equal(armResponse.jsonBody.status, 'armed');
  assert.equal(armResponse.jsonBody.events_expected, 4);
  assert.equal(armResponse.jsonBody.profile.terminal_id, 'A01-PAY-014');
  assert.equal(armResponse.jsonBody.trigger.path, '/customer/book-ticket');

  const armedLog = harness.records.find((record) => record.message === 'dns_tunneling_armed');
  assert.ok(armedLog);
  assert.equal(armedLog.terminal_id, 'A01-PAY-014');
  assert.equal(armedLog.mitre_id, 'T1071.004');

  const bookingRequest = createRequest({
    method: 'POST',
    originalUrl: '/api/customer/bookings',
    body: {
      passenger_name: 'Customer Rider',
      passenger_contact: '9999900000',
      route_name: 'Majestic - Whitefield',
      source_stop: 'Majestic',
      destination_stop: 'Whitefield',
      travel_date: '2026-04-06T10:00',
      bus_number: 'KA-01-FM-1142',
      seat_number: '14B',
      payment_mode: 'Card',
      booking_channel: 'kiosk',
      payment_terminal_id: 'A01-PAY-014',
      fare: '45',
      operator_label: 'customer-web-booking',
      travel_note: 'dns trigger test'
    },
    session: createSession({
      user: {
        id: 3,
        username: 'customer',
        role: 'customer'
      }
    })
  });
  const bookingResponse = createResponse();

  await invoke(harness.controllers.postCustomerBooking, bookingRequest, bookingResponse);

  assert.equal(bookingResponse.jsonBody.scenario_signals.dns_tunneling.triggered, true);
  assert.equal(bookingResponse.jsonBody.scenario_signals.dns_tunneling.events_emitted, 4);

  const dnsLogs = harness.records.filter((record) => record.message === 'dns_tunneling_suspected');
  assert.equal(dnsLogs.length, 4);
  assert.equal(dnsLogs[0].terminal_id, 'A01-PAY-014');
  assert.equal(dnsLogs[0].terminal_segment, 'payment-vlan');
  assert.equal(dnsLogs[0].malicious_domain, 'collector.attacker-domain.com');
  assert.equal(dnsLogs[0].query_type, 'TXT');
  assert.ok(dnsLogs[0].query.includes('.collector.attacker-domain.com'));
  assert.equal(dnsLogs[0].mitre_id, 'T1071.004');

  await harness.close();
});

test('payment skimming can be armed by admin and triggered by a matching customer payment', async () => {
  const harness = await createHarness({
    sleep: async () => {}
  });
  const armRequest = createRequest({
    method: 'POST',
    originalUrl: '/api/simulations/payment-skimming',
    body: {
      terminal_id: 'A01-PAY-022',
      terminal_site: 'Central Station North Gate',
      firmware_version: 'fw-7.14.2',
      tamper_source: 'contactless-sidecar',
      skimmed_card_count: '3',
      collector_domain: 'collector.attacker-domain.com',
      bytes_sent: '20480',
      read_interval_ms: '5',
      operator_note: 'skimming drill'
    }
  });
  const armResponse = createResponse();

  await invoke(harness.controllers.postPaymentSkimming, armRequest, armResponse);

  assert.equal(armResponse.statusCode, 202);
  assert.equal(armResponse.jsonBody.status, 'armed');
  assert.equal(armResponse.jsonBody.events_expected, 4);
  assert.equal(armResponse.jsonBody.profile.collector_domain, 'collector.attacker-domain.com');
  assert.equal(armResponse.jsonBody.trigger.path, '/customer/book-ticket');

  const tamperLog = harness.records.find((record) => record.message === 'payment_terminal_tamper');
  assert.ok(tamperLog);
  assert.equal(tamperLog.terminal_id, 'A01-PAY-022');
  assert.equal(tamperLog.mitre_id, 'T1056');

  const bookingRequest = createRequest({
    method: 'POST',
    originalUrl: '/api/customer/bookings',
    body: {
      passenger_name: 'Customer Rider',
      passenger_contact: '9999900000',
      route_name: 'Silk Board - Hebbal',
      source_stop: 'Silk Board',
      destination_stop: 'Hebbal',
      travel_date: '2026-04-06T10:30',
      bus_number: 'KA-01-FM-2308',
      seat_number: '05A',
      payment_mode: 'Card',
      booking_channel: 'kiosk',
      payment_terminal_id: 'A01-PAY-022',
      fare: '35',
      operator_label: 'customer-web-booking',
      travel_note: 'skimming trigger test'
    },
    session: createSession({
      user: {
        id: 3,
        username: 'customer',
        role: 'customer'
      }
    })
  });
  const bookingResponse = createResponse();

  await invoke(harness.controllers.postCustomerBooking, bookingRequest, bookingResponse);

  assert.equal(bookingResponse.jsonBody.scenario_signals.payment_skimming.triggered, true);
  assert.equal(bookingResponse.jsonBody.scenario_signals.payment_skimming.events_emitted, 4);

  const readLogs = harness.records.filter((record) => record.message === 'payment_card_read_anomaly');
  const exfilLog = harness.records.find((record) => record.message === 'payment_data_exfil_attempt');

  assert.equal(readLogs.length, 3);
  assert.equal(readLogs[0].tamper_source, 'contactless-sidecar');
  assert.equal(readLogs[0].terminal_id, 'A01-PAY-022');
  assert.equal(readLogs[0].mitre_id, 'T1056');
  assert.equal(exfilLog.dest_domain, 'collector.attacker-domain.com');
  assert.equal(exfilLog.bytes_sent, 20480);
  assert.equal(exfilLog.mitre_id, 'T1041');

  await harness.close();
});

test('gps spoofing can be armed by admin and triggered by a matching customer bus lookup', async () => {
  const harness = await createHarness({
    sleep: async () => {}
  });
  const armRequest = createRequest({
    method: 'POST',
    originalUrl: '/api/simulations/gps-spoofing',
    body: {
      bus_number: 'KA-01-FM-5520',
      route_name: 'Jayanagar - Airport',
      expected_location: 'Jayanagar Depot',
      spoofed_location: 'Airport Runway Access Road',
      anomaly_count: '4',
      jump_distance_km: '18',
      satellite_count: '3',
      displayed_stop: 'MG Road',
      schedule_delta_min: '22',
      anomaly_interval_ms: '5',
      operator_note: 'gps drill'
    }
  });
  const armResponse = createResponse();

  await invoke(harness.controllers.postGpsSpoofing, armRequest, armResponse);

  assert.equal(armResponse.statusCode, 202);
  assert.equal(armResponse.jsonBody.status, 'armed');
  assert.equal(armResponse.jsonBody.events_expected, 5);
  assert.equal(armResponse.jsonBody.profile.bus_number, 'KA-01-FM-5520');
  assert.equal(armResponse.jsonBody.trigger.path, '/customer/buses');

  const armedLog = harness.records.find((record) => record.message === 'gps_spoofing_armed');
  assert.ok(armedLog);
  assert.equal(armedLog.bus_number, 'KA-01-FM-5520');
  assert.equal(armedLog.mitre_id, 'T1565.002');

  const lookupRequest = createRequest({
    method: 'GET',
    originalUrl: '/api/customer/buses?route_name=Airport&limit=5',
    query: {
      route_name: 'Airport',
      limit: '5',
      operator_label: 'customer-bus-refresh'
    },
    session: createSession({
      user: {
        id: 3,
        username: 'customer',
        role: 'customer'
      }
    })
  });
  const lookupResponse = createResponse();

  await invoke(harness.controllers.getCustomerBuses, lookupRequest, lookupResponse);

  assert.equal(lookupResponse.jsonBody.scenario_summary.spoofed_count, 1);
  assert.equal(lookupResponse.jsonBody.buses[0].bus_number, 'KA-01-FM-5520');
  assert.equal(lookupResponse.jsonBody.buses[0].route_integrity, 'spoofed');
  assert.equal(lookupResponse.jsonBody.buses[0].displayed_location, 'Airport Runway Access Road');
  assert.equal(lookupResponse.jsonBody.buses[0].displayed_stop, 'MG Road');

  const anomalyLogs = harness.records.filter((record) => record.message === 'gps_signal_anomaly');
  const ghostLog = harness.records.find((record) => record.message === 'ghost_bus_projection');

  assert.equal(anomalyLogs.length, 4);
  assert.equal(anomalyLogs[0].expected_location, 'Jayanagar Depot');
  assert.equal(anomalyLogs[0].spoofed_location, 'Airport Runway Access Road');
  assert.equal(anomalyLogs[0].mitre_id, 'T1565.002');
  assert.equal(ghostLog.displayed_stop, 'MG Road');
  assert.equal(ghostLog.schedule_delta_min, 22);
  assert.equal(ghostLog.mitre_id, 'T1565.003');

  await harness.close();
});

test('ransomware controller returns the configured profile and emits custom ransomware fields', async () => {
  const harness = await createHarness({
    sleep: async () => {}
  });
  const request = createRequest({
    method: 'POST',
    originalUrl: '/api/simulations/ransomware',
    body: {
      asset_tag: 'A04',
      operation_name: 'Depot drill alpha',
      service_name: 'TransitUpdateSvc',
      encrypted_file_count: '4',
      file_extension: '.vault',
      target_directory: 'C:\\TransitData\\DepotAlpha',
      ransom_note_name: 'RESTORE_NOW.txt',
      dest_ip: '198.51.100.44',
      dest_port: '8443',
      file_delay_ms: '12',
      beacon_delay_ms: '24',
      encryption_message: 'encryption burst in progress',
      beacon_message: 'scheduled beacon every 45s'
    }
  });
  const response = createResponse();

  await invoke(harness.controllers.postRansomware, request, response);
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(response.statusCode, 202);
  assert.equal(response.jsonBody.events_expected, 7);
  assert.equal(response.jsonBody.profile.service_name, 'TransitUpdateSvc');
  assert.equal(response.jsonBody.profile.file_extension, '.vault');

  const serviceLog = harness.records.find((record) => record.event_id === 7045);
  const fileWriteLogs = harness.records.filter((record) => record.action === 'file_write');
  const noteLog = harness.records.find((record) => record.action === 'file_create');
  const beaconLog = harness.records.find((record) => record.dest_port === 8443);

  assert.ok(serviceLog);
  assert.equal(serviceLog.service_name, 'TransitUpdateSvc');
  assert.equal(serviceLog.operation_name, 'Depot drill alpha');
  assert.equal(serviceLog.mitre_id, 'T1543.003');
  assert.equal(fileWriteLogs.length, 4);
  assert.equal(fileWriteLogs[0].file_extension, '.vault');
  assert.equal(fileWriteLogs[0].mitre_id, 'T1486');
  assert.equal(noteLog.file_name, 'RESTORE_NOW.txt');
  assert.equal(noteLog.mitre_id, 'T1486');
  assert.equal(beaconLog.dest_ip, '198.51.100.44');
  assert.equal(beaconLog.mitre_id, 'T1071');

  await harness.close();
});

test('ransomware simulation emits the expected event order and pacing', async () => {
  const recordedSleeps = [];
  const records = [];
  const logEvent = createLogger({
    sink: {
      write(line) {
        records.push(JSON.parse(line));
      }
    }
  });
  const simulations = createSimulationManager({
    logEvent,
    sleep: async (durationMs) => {
      recordedSleeps.push(durationMs);
    }
  });

  await simulations.emitRansomware({ srcIp: '127.0.0.1' });

  assert.equal(records[0].event_id, 7045);
  assert.equal(records.filter((record) => record.action === 'file_write').length, 50);
  assert.equal(records[51].file_name, 'DECRYPT_FILES.txt');
  assert.equal(records[52].dest_port, 443);
  assert.equal(recordedSleeps.length, 51);
  assert.equal(recordedSleeps[0], 80);
  assert.equal(recordedSleeps[49], 80);
  assert.equal(recordedSleeps[50], 900);
});

test('dns simulator emits TXT query logs while active and stops after logout', async () => {
  const records = [];
  const logEvent = createLogger({
    sink: {
      write(line) {
        records.push(JSON.parse(line));
      }
    }
  });
  const simulations = createSimulationManager({
    logEvent,
    dnsIntervalMs: 10,
    randomLabelFactory: () => 'a'.repeat(100)
  });

  simulations.startDnsSession({
    sessionId: 'session-1',
    srcIp: '127.0.0.1',
    username: 'admin'
  });

  await new Promise((resolve) => setTimeout(resolve, 25));
  simulations.stopDnsSession('session-1');
  const countAtStop = records.length;

  await new Promise((resolve) => setTimeout(resolve, 25));

  assert.ok(countAtStop >= 1);
  assert.equal(records.length, countAtStop);
  assert.equal(records[0].protocol, 'DNS');
  assert.equal(records[0].query_type, 'TXT');
  assert.equal(records[0].query_length, 120);
  assert.equal(records[0].mitre_id, 'T1071.004');
});
