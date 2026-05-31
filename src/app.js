const crypto = require('crypto');
const path = require('path');
const express = require('express');
const session = require('express-session');
const { createLogger, getSourceIp, isLocalhost } = require('./logger');
const { createSimulationManager } = require('./simulations');

function severityFromStatus(statusCode) {
  if (statusCode >= 500) {
    return 'ERROR';
  }

  if (statusCode >= 400) {
    return 'WARNING';
  }

  return 'INFO';
}

function isAdminRole(role) {
  return role === 'admin';
}

function isCustomerRole(role) {
  return role === 'customer';
}

function resolveDashboardPath(user) {
  if (!user) {
    return '/login';
  }

  if (isAdminRole(user.role)) {
    return '/admin/dashboard';
  }

  if (isCustomerRole(user.role)) {
    return '/customer/dashboard';
  }

  return '/login';
}

function normalizeText(value, fallback = '', maxLength = 200) {
  const normalized = String(value == null ? '' : value).trim();

  if (!normalized) {
    return fallback;
  }

  return normalized.slice(0, maxLength);
}

function normalizeInteger(value, defaultValue, min, max) {
  const parsed = Number.parseInt(String(value == null ? '' : value), 10);

  if (!Number.isFinite(parsed)) {
    return defaultValue;
  }

  return Math.min(max, Math.max(min, parsed));
}

function normalizeDecimal(value, defaultValue, min, max) {
  const parsed = Number.parseFloat(String(value == null ? '' : value));

  if (!Number.isFinite(parsed)) {
    return defaultValue;
  }

  return Math.min(max, Math.max(min, Number(parsed.toFixed(2))));
}

function normalizeStatus(value) {
  const normalized = normalizeText(value, 'all', 24).toLowerCase();
  const allowed = new Set(['all', 'booked', 'issued', 'validated']);

  if (!allowed.has(normalized)) {
    return 'all';
  }

  return normalized;
}

function normalizeVehicleStatus(value) {
  const normalized = normalizeText(value, 'all', 24).toLowerCase();
  const allowed = new Set(['all', 'in_service', 'boarding', 'layover']);

  if (!allowed.has(normalized)) {
    return 'all';
  }

  return normalized;
}

function normalizePaymentMode(value) {
  const normalized = normalizeText(value, 'UPI', 24);
  const allowed = new Set(['UPI', 'Card', 'Cash', 'CorporatePass']);

  if (!allowed.has(normalized)) {
    return 'UPI';
  }

  return normalized;
}

function normalizeBookingChannel(value) {
  const normalized = normalizeText(value, 'mobile_app', 24);
  const allowed = new Set(['mobile_app', 'kiosk', 'counter', 'partner_portal']);

  if (!allowed.has(normalized)) {
    return 'mobile_app';
  }

  return normalized;
}

function normalizeExtension(value, fallback = '.locked') {
  const normalized = normalizeText(value, fallback, 24);

  if (!normalized.startsWith('.')) {
    return `.${normalized}`;
  }

  return normalized;
}

function buildTicketFilters(query = {}) {
  return {
    route_name: normalizeText(query.route_name, '', 120),
    passenger_name: normalizeText(query.passenger_name, '', 120),
    bus_number: normalizeText(query.bus_number, '', 60),
    source_stop: normalizeText(query.source_stop, '', 80),
    destination_stop: normalizeText(query.destination_stop, '', 80),
    status: normalizeStatus(query.status),
    issued_after: normalizeText(query.issued_after, '', 40),
    limit: normalizeInteger(query.limit, 25, 1, 200),
    operator_label: normalizeText(query.operator_label, '', 80)
  };
}

function buildBusFilters(query = {}) {
  return {
    route_name: normalizeText(query.route_name, '', 120),
    origin_stop: normalizeText(query.origin_stop, '', 80),
    destination_stop: normalizeText(query.destination_stop, '', 80),
    vehicle_status: normalizeVehicleStatus(query.vehicle_status),
    limit: normalizeInteger(query.limit, 12, 1, 100),
    operator_label: normalizeText(query.operator_label, '', 80)
  };
}

function buildCustomerBookingProfile(body = {}, sessionUser) {
  const sessionUsername = sessionUser && sessionUser.username ? sessionUser.username : null;

  return {
    passenger_name: normalizeText(body.passenger_name, sessionUsername || 'Customer Rider', 120),
    passenger_contact: normalizeText(body.passenger_contact, '9876500999', 30),
    route_name: normalizeText(body.route_name, 'Majestic - Whitefield', 120),
    source_stop: normalizeText(body.source_stop, 'Majestic', 80),
    destination_stop: normalizeText(body.destination_stop, 'Whitefield', 80),
    travel_date: normalizeText(body.travel_date, '2026-04-06T10:00', 40),
    bus_number: normalizeText(body.bus_number, 'KA-01-FM-1142', 60),
    seat_number: normalizeText(body.seat_number, '14B', 20),
    payment_mode: normalizePaymentMode(body.payment_mode),
    booking_channel: normalizeBookingChannel(body.booking_channel),
    payment_terminal_id: normalizeText(body.payment_terminal_id, 'A01-PAY-014', 60),
    fare: normalizeDecimal(body.fare, 45, 0, 5000),
    operator_label: normalizeText(body.operator_label, 'customer-web-booking', 80),
    travel_note: normalizeText(body.travel_note, 'Morning commute booking from portal', 200)
  };
}

function buildTicketStatusLookup(query = {}) {
  return {
    ticket_number: normalizeText(query.ticket_number, '', 40),
    passenger_name: normalizeText(query.passenger_name, '', 120),
    passenger_contact: normalizeText(query.passenger_contact, '', 30),
    bus_number: normalizeText(query.bus_number, '', 60),
    status: normalizeStatus(query.status),
    limit: normalizeInteger(query.limit, 10, 1, 50),
    operator_label: normalizeText(query.operator_label, 'customer-status-check', 80)
  };
}

function buildAuthSequenceProfile(body = {}, sessionUser) {
  const sessionUsername = sessionUser && sessionUser.username ? sessionUser.username : null;

  return {
    username: normalizeText(body.username, sessionUsername || 'dispatcher.scheduler', 80),
    failure_count: normalizeInteger(body.failure_count, 10, 1, 100),
    workstation_name: normalizeText(body.workstation_name, 'BTA-OPS-07', 80),
    source_label: normalizeText(body.source_label, 'ops-console', 80),
    failure_reason: normalizeText(body.failure_reason, 'bad_password', 80),
    success_logon_type: normalizeText(body.success_logon_type, 'Interactive', 80),
    correlation_key: normalizeText(body.correlation_key, 'AUTH-BTA-001', 120),
    operator_note: normalizeText(body.operator_note, 'Manual auth drill from console', 200)
  };
}

function buildRansomwareProfile(body = {}) {
  return {
    asset_tag: normalizeText(body.asset_tag, 'A04', 40),
    operation_name: normalizeText(body.operation_name, 'BTA central workshop', 120),
    service_name: normalizeText(body.service_name, 'SysUpdate1', 80),
    encrypted_file_count: normalizeInteger(body.encrypted_file_count, 50, 1, 200),
    file_extension: normalizeExtension(body.file_extension, '.locked'),
    target_directory: normalizeText(body.target_directory, 'C:\\TransitData\\Operations', 180),
    ransom_note_name: normalizeText(body.ransom_note_name, 'DECRYPT_FILES.txt', 120),
    dest_ip: normalizeText(body.dest_ip, 'malicious_c2_ip', 80),
    dest_port: normalizeInteger(body.dest_port, 443, 1, 65535),
    file_delay_ms: normalizeInteger(body.file_delay_ms, 80, 10, 5000),
    beacon_delay_ms: normalizeInteger(body.beacon_delay_ms, 900, 10, 10000),
    encryption_message: normalizeText(
      body.encryption_message,
      'rapid file encryption detected',
      160
    ),
    beacon_message: normalizeText(body.beacon_message, 'beaconing traffic every 60s', 160)
  };
}

function buildDnsTunnelingProfile(body = {}) {
  return {
    terminal_id: normalizeText(body.terminal_id, 'A01-PAY-014', 60),
    terminal_site: normalizeText(body.terminal_site, 'Majestic Gate 2', 120),
    terminal_segment: normalizeText(body.terminal_segment, 'payment-vlan', 60),
    malicious_domain: normalizeText(body.malicious_domain, 'attacker-domain.com', 120),
    query_count: normalizeInteger(body.query_count, 12, 1, 100),
    label_length: normalizeInteger(body.label_length, 104, 32, 180),
    query_type: normalizeText(body.query_type, 'TXT', 16),
    query_interval_ms: normalizeInteger(body.query_interval_ms, 40, 0, 5000),
    operator_note: normalizeText(
      body.operator_note,
      'payment-terminal dns exfiltration drill',
      200
    )
  };
}

function buildPaymentSkimmingProfile(body = {}) {
  return {
    terminal_id: normalizeText(body.terminal_id, 'A01-PAY-022', 60),
    terminal_site: normalizeText(body.terminal_site, 'Central Station North Gate', 120),
    firmware_version: normalizeText(body.firmware_version, 'fw-7.14.2', 60),
    tamper_source: normalizeText(body.tamper_source, 'contactless-sidecar', 80),
    skimmed_card_count: normalizeInteger(body.skimmed_card_count, 6, 1, 100),
    collector_domain: normalizeText(body.collector_domain, 'collector.attacker-domain.com', 120),
    bytes_sent: normalizeInteger(body.bytes_sent, 18432, 100, 5000000),
    read_interval_ms: normalizeInteger(body.read_interval_ms, 35, 0, 5000),
    operator_note: normalizeText(body.operator_note, 'payment skimming drill', 200)
  };
}

function buildGpsSpoofingProfile(body = {}) {
  return {
    bus_number: normalizeText(body.bus_number, 'KA-01-FM-5520', 60),
    route_name: normalizeText(body.route_name, 'Jayanagar - Airport', 120),
    expected_location: normalizeText(body.expected_location, 'Jayanagar Depot', 120),
    spoofed_location: normalizeText(body.spoofed_location, 'Airport Runway Access Road', 120),
    anomaly_count: normalizeInteger(body.anomaly_count, 5, 1, 50),
    jump_distance_km: normalizeInteger(body.jump_distance_km, 18, 1, 500),
    satellite_count: normalizeInteger(body.satellite_count, 3, 1, 20),
    displayed_stop: normalizeText(body.displayed_stop, 'MG Road', 120),
    schedule_delta_min: normalizeInteger(body.schedule_delta_min, 22, 1, 600),
    anomaly_interval_ms: normalizeInteger(body.anomaly_interval_ms, 50, 0, 5000),
    operator_note: normalizeText(body.operator_note, 'gps spoofing drill', 200)
  };
}

function createTicketNumber() {
  return `BTA-${Date.now().toString().slice(-6)}${Math.floor(Math.random() * 900) + 100}`;
}

function createAccessLogMiddleware(logEvent) {
  return function accessLogMiddleware(req, res, next) {
    const startedAt = Date.now();

    res.on('finish', () => {
      logEvent({
        severity: severityFromStatus(res.statusCode),
        src_ip: getSourceIp(req),
        message: 'http_access',
        method: req.method,
        path: req.originalUrl,
        status_code: res.statusCode,
        duration_ms: Date.now() - startedAt
      });
    });

    next();
  };
}

function createControllers({ database, logEvent, simulations, simulationSecret }) {
  function requireAuth(req, res, next) {
    if (req.session.user) {
      next();
      return;
    }

    res.redirect('/login');
  }

  function requireAdmin(req, res, next) {
    if (req.session.user && isAdminRole(req.session.user.role)) {
      next();
      return;
    }

    res.redirect(resolveDashboardPath(req.session.user));
  }

  function requireCustomer(req, res, next) {
    if (req.session.user && isCustomerRole(req.session.user.role)) {
      next();
      return;
    }

    res.redirect(resolveDashboardPath(req.session.user));
  }

  function requireSimulationAccess(req, res, next) {
    const srcIp = getSourceIp(req);
    const providedSecret = req.get('x-simulation-secret') || req.body.simulation_secret;

    if (isLocalhost(srcIp)) {
      next();
      return;
    }

    if (req.session.user && isAdminRole(req.session.user.role) && providedSecret === simulationSecret) {
      next();
      return;
    }

    res.status(403).json({ error: 'Forbidden' });
  }

  function root(req, res) {
    if (req.session.user) {
      res.redirect('/dashboard');
      return;
    }

    res.redirect('/login');
  }

  function getLogin(req, res) {
    if (req.session.user) {
      res.redirect('/dashboard');
      return;
    }

    res.render('login', { error: null });
  }

  async function postLogin(req, res, next) {
    const username = normalizeText(req.body.username, '', 120);
    const password = String(req.body.password || '');
    const srcIp = getSourceIp(req);

    try {
      const user = await database.get(
        'SELECT id, username, role FROM users WHERE username = ? AND password = ?',
        [username, password]
      );

      if (!user) {
        logEvent({
          severity: 'WARNING',
          src_ip: srcIp,
          event_id: 4625,
          username: username || 'unknown',
          status: 'failed'
        });
        res.status(401).render('login', { error: 'Invalid credentials' });
        return;
      }

      req.session.user = {
        id: user.id,
        username: user.username,
        role: user.role
      };

      req.session.save((error) => {
        if (error) {
          next(error);
          return;
        }

        logEvent({
          severity: 'INFO',
          src_ip: srcIp,
          event_id: 4624,
          username: user.username,
          status: 'success'
        });
        simulations.startDnsSession({
          sessionId: req.session.id,
          srcIp,
          username: user.username
        });
        res.redirect(resolveDashboardPath(req.session.user));
      });
    } catch (error) {
      next(error);
    }
  }

  function postLogout(req, res, next) {
    simulations.stopDnsSession(req.session.id);
    req.session.destroy((error) => {
      if (error) {
        next(error);
        return;
      }

      res.clearCookie('connect.sid');
      res.redirect('/login');
    });
  }

  function getDashboard(req, res) {
    res.redirect(resolveDashboardPath(req.session.user));
  }

  function getAdminDashboard(req, res) {
    res.render('admin-dashboard', {
      simulationSecret
    });
  }

  function getCustomerDashboard(req, res) {
    res.render('customer-dashboard');
  }

  function getTicketConsole(req, res) {
    res.render('tickets-console', {
      simulationSecret
    });
  }

  function getAuthSequenceConsole(req, res) {
    res.render('auth-sequence-console', {
      simulationSecret
    });
  }

  function getRansomwareConsole(req, res) {
    res.render('ransomware-console', {
      simulationSecret
    });
  }

  function getDnsTunnelingConsole(req, res) {
    res.render('dns-tunneling-console', {
      simulationSecret
    });
  }

  function getPaymentSkimmingConsole(req, res) {
    res.render('payment-skimming-console', {
      simulationSecret
    });
  }

  function getGpsSpoofingConsole(req, res) {
    res.render('gps-spoofing-console', {
      simulationSecret
    });
  }

  function getBookTicketConsole(req, res) {
    res.render('book-ticket-console');
  }

  function getBusesConsole(req, res) {
    res.render('buses-console');
  }

  function getTicketStatusConsole(req, res) {
    res.render('ticket-status-console');
  }

  async function getPassengerTickets(req, res, next) {
    const filters = buildTicketFilters(req.query);
    const srcIp = getSourceIp(req);

    try {
      const clauses = [];
      const params = [];

      if (filters.route_name) {
        clauses.push('route_name LIKE ?');
        params.push(`%${filters.route_name}%`);
      }

      if (filters.passenger_name) {
        clauses.push('passenger_name LIKE ?');
        params.push(`%${filters.passenger_name}%`);
      }

      if (filters.bus_number) {
        clauses.push('bus_number LIKE ?');
        params.push(`%${filters.bus_number}%`);
      }

      if (filters.source_stop) {
        clauses.push('source_stop LIKE ?');
        params.push(`%${filters.source_stop}%`);
      }

      if (filters.destination_stop) {
        clauses.push('destination_stop LIKE ?');
        params.push(`%${filters.destination_stop}%`);
      }

      if (filters.status !== 'all') {
        clauses.push('status = ?');
        params.push(filters.status);
      }

      if (filters.issued_after) {
        clauses.push('issued_at >= ?');
        params.push(filters.issued_after);
      }

      const whereClause = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
      const tickets = await database.all(
        `
          SELECT
            ticket_number,
            route_name,
            passenger_name,
            passenger_contact,
            source_stop,
            destination_stop,
            bus_number,
            seat_number,
            payment_mode,
            booking_channel,
            payment_terminal_id,
            status,
            fare,
            issued_at,
            travel_date
          FROM tickets
          ${whereClause}
          ORDER BY issued_at DESC
          LIMIT ?
        `,
        [...params, filters.limit]
      );

      logEvent({
        severity: 'INFO',
        src_ip: srcIp,
        message: 'ticket_console_query',
        operator_label: filters.operator_label || null,
        route_name_filter: filters.route_name || null,
        passenger_name_filter: filters.passenger_name || null,
        bus_number_filter: filters.bus_number || null,
        source_stop_filter: filters.source_stop || null,
        destination_stop_filter: filters.destination_stop || null,
        status_filter: filters.status,
        issued_after: filters.issued_after || null,
        limit: filters.limit,
        result_count: tickets.length,
        requested_by: req.session.user && req.session.user.username ? req.session.user.username : 'anonymous'
      });

      res.json({
        fetched_at: new Date().toISOString(),
        filters,
        total: tickets.length,
        tickets
      });
    } catch (error) {
      next(error);
    }
  }

  async function postCustomerBooking(req, res, next) {
    const srcIp = getSourceIp(req);
    const profile = buildCustomerBookingProfile(req.body, req.session.user);
    const ticketNumber = createTicketNumber();
    const issuedAt = new Date().toISOString();

    try {
      await database.run(
        `
          INSERT INTO tickets (
            ticket_number,
            route_name,
            passenger_name,
            passenger_contact,
            source_stop,
            destination_stop,
            bus_number,
            seat_number,
            payment_mode,
            booking_channel,
            payment_terminal_id,
            status,
            fare,
            issued_at,
            travel_date,
            created_by_user_id
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `,
        [
          ticketNumber,
          profile.route_name,
          profile.passenger_name,
          profile.passenger_contact,
          profile.source_stop,
          profile.destination_stop,
          profile.bus_number,
          profile.seat_number,
          profile.payment_mode,
          profile.booking_channel,
          profile.payment_terminal_id,
          'booked',
          profile.fare,
          issuedAt,
          profile.travel_date,
          req.session.user.id
        ]
      );

      logEvent({
        severity: 'INFO',
        src_ip: srcIp,
        message: 'customer_ticket_booking',
        ticket_number: ticketNumber,
        route_name: profile.route_name,
        passenger_name: profile.passenger_name,
        passenger_contact: profile.passenger_contact,
        source_stop: profile.source_stop,
        destination_stop: profile.destination_stop,
        bus_number: profile.bus_number,
        seat_number: profile.seat_number,
        payment_mode: profile.payment_mode,
        booking_channel: profile.booking_channel,
        payment_terminal_id: profile.payment_terminal_id,
        fare: profile.fare,
        operator_label: profile.operator_label,
        requested_by: req.session.user.username,
        travel_note: profile.travel_note
      });

      const paymentContext = {
        ticketNumber,
        terminalId: profile.payment_terminal_id,
        fare: profile.fare,
        paymentMode: profile.payment_mode
      };
      const paymentSkimming = simulations.triggerPaymentSkimming({
        srcIp,
        context: paymentContext
      });
      const dnsTunneling = simulations.triggerDnsForPayment({
        srcIp,
        context: paymentContext
      });

      res.status(201).json({
        status: 'accepted',
        booking: {
          ticket_number: ticketNumber,
          status: 'booked',
          issued_at: issuedAt,
          ...profile
        },
        scenario_signals: {
          payment_skimming: paymentSkimming,
          dns_tunneling: dnsTunneling
        }
      });
    } catch (error) {
      next(error);
    }
  }

  async function getCustomerBuses(req, res, next) {
    const filters = buildBusFilters(req.query);
    const srcIp = getSourceIp(req);

    try {
      const clauses = [];
      const params = [];

      if (filters.route_name) {
        clauses.push('route_name LIKE ?');
        params.push(`%${filters.route_name}%`);
      }

      if (filters.origin_stop) {
        clauses.push('origin_stop LIKE ?');
        params.push(`%${filters.origin_stop}%`);
      }

      if (filters.destination_stop) {
        clauses.push('destination_stop LIKE ?');
        params.push(`%${filters.destination_stop}%`);
      }

      if (filters.vehicle_status !== 'all') {
        clauses.push('vehicle_status = ?');
        params.push(filters.vehicle_status);
      }

      const whereClause = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
      const buses = await database.all(
        `
          SELECT
            bus_number,
            route_name,
            origin_stop,
            destination_stop,
            next_departure,
            occupancy_percent,
            vehicle_status,
            driver_name
          FROM buses
          ${whereClause}
          ORDER BY next_departure ASC
          LIMIT ?
        `,
        [...params, filters.limit]
      );
      const renderedBuses = simulations.applyGpsSpoofing({
        srcIp,
        buses
      });
      const spoofedCount = renderedBuses.filter((bus) => bus.route_integrity === 'spoofed').length;

      logEvent({
        severity: 'INFO',
        src_ip: srcIp,
        message: 'customer_bus_lookup',
        route_name_filter: filters.route_name || null,
        origin_stop_filter: filters.origin_stop || null,
        destination_stop_filter: filters.destination_stop || null,
        vehicle_status_filter: filters.vehicle_status,
        limit: filters.limit,
        operator_label: filters.operator_label || null,
        result_count: renderedBuses.length,
        spoofed_result_count: spoofedCount,
        requested_by: req.session.user.username
      });

      res.json({
        fetched_at: new Date().toISOString(),
        filters,
        total: renderedBuses.length,
        scenario_summary: {
          spoofed_count: spoofedCount
        },
        buses: renderedBuses
      });
    } catch (error) {
      next(error);
    }
  }

  async function getCustomerTicketStatus(req, res, next) {
    const lookup = buildTicketStatusLookup(req.query);
    const srcIp = getSourceIp(req);

    try {
      const clauses = [];
      const params = [];

      if (lookup.ticket_number) {
        clauses.push('ticket_number = ?');
        params.push(lookup.ticket_number);
      }

      if (lookup.passenger_name) {
        clauses.push('passenger_name LIKE ?');
        params.push(`%${lookup.passenger_name}%`);
      }

      if (lookup.passenger_contact) {
        clauses.push('passenger_contact LIKE ?');
        params.push(`%${lookup.passenger_contact}%`);
      }

      if (lookup.bus_number) {
        clauses.push('bus_number LIKE ?');
        params.push(`%${lookup.bus_number}%`);
      }

      if (lookup.status !== 'all') {
        clauses.push('status = ?');
        params.push(lookup.status);
      }

      const whereClause = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
      const tickets = await database.all(
        `
          SELECT
            ticket_number,
            route_name,
            passenger_name,
            passenger_contact,
            source_stop,
            destination_stop,
            bus_number,
            seat_number,
            payment_mode,
            booking_channel,
            payment_terminal_id,
            status,
            fare,
            issued_at,
            travel_date
          FROM tickets
          ${whereClause}
          ORDER BY issued_at DESC
          LIMIT ?
        `,
        [...params, lookup.limit]
      );

      logEvent({
        severity: 'INFO',
        src_ip: srcIp,
        message: 'customer_ticket_status_lookup',
        ticket_number_filter: lookup.ticket_number || null,
        passenger_name_filter: lookup.passenger_name || null,
        passenger_contact_filter: lookup.passenger_contact || null,
        bus_number_filter: lookup.bus_number || null,
        status_filter: lookup.status,
        operator_label: lookup.operator_label,
        result_count: tickets.length,
        requested_by: req.session.user.username
      });

      res.json({
        fetched_at: new Date().toISOString(),
        filters: lookup,
        total: tickets.length,
        tickets
      });
    } catch (error) {
      next(error);
    }
  }

  function postAuthSequence(req, res) {
    const srcIp = getSourceIp(req);
    const profile = buildAuthSequenceProfile(req.body, req.session.user);
    const summary = simulations.emitAuthSequence({
      srcIp,
      username: profile.username,
      failureCount: profile.failure_count,
      workstationName: profile.workstation_name,
      sourceLabel: profile.source_label,
      failureReason: profile.failure_reason,
      successLogonType: profile.success_logon_type,
      correlationKey: profile.correlation_key,
      operatorNote: profile.operator_note
    });

    res.status(202).json({
      status: 'accepted',
      events_emitted: summary.events_emitted,
      config: profile
    });
  }

  function postDnsTunneling(req, res) {
    const profile = buildDnsTunnelingProfile(req.body);
    const summary = simulations.armDnsProfile(profile);

    res.status(202).json({
      status: summary.status,
      armed_signal: 'dns_tunneling_armed',
      events_expected: summary.events_on_payment,
      trigger: {
        path: '/customer/book-ticket',
        action: 'Submit a customer booking with the same payment terminal ID to generate the DNS burst.',
        payment_terminal_id: profile.terminal_id
      },
      profile
    });
  }

  function postRansomware(req, res) {
    const srcIp = getSourceIp(req);
    const profile = buildRansomwareProfile(req.body);

    simulations.emitRansomware({
      srcIp,
      assetTag: profile.asset_tag,
      operationName: profile.operation_name,
      serviceName: profile.service_name,
      encryptedFileCount: profile.encrypted_file_count,
      fileExtension: profile.file_extension,
      targetDirectory: profile.target_directory,
      ransomNoteName: profile.ransom_note_name,
      destIp: profile.dest_ip,
      destPort: profile.dest_port,
      fileDelayMs: profile.file_delay_ms,
      beaconDelayMs: profile.beacon_delay_ms,
      encryptionMessage: profile.encryption_message,
      beaconMessage: profile.beacon_message
    }).catch((error) => {
      logEvent({
        severity: 'ERROR',
        src_ip: srcIp,
        message: 'ransomware_simulation_failed',
        error: error.message
      });
    });

    res.status(202).json({
      status: 'accepted',
      events_expected: profile.encrypted_file_count + 3,
      profile
    });
  }

  function postPaymentSkimming(req, res) {
    const profile = buildPaymentSkimmingProfile(req.body);
    const summary = simulations.armPaymentSkimming(profile);

    res.status(202).json({
      status: summary.status,
      armed_signal: 'payment_terminal_tamper',
      events_expected: summary.events_on_payment,
      trigger: {
        path: '/customer/book-ticket',
        action: 'Submit a customer booking with the same payment terminal ID to generate card-read and exfiltration evidence.',
        payment_terminal_id: profile.terminal_id
      },
      profile
    });
  }

  function postGpsSpoofing(req, res) {
    const profile = buildGpsSpoofingProfile(req.body);
    const summary = simulations.armGpsSpoofing(profile);

    res.status(202).json({
      status: summary.status,
      armed_signal: 'gps_spoofing_armed',
      events_expected: summary.events_on_lookup,
      trigger: {
        path: '/customer/buses',
        action: 'Run a customer bus lookup that includes the same bus number or route to surface the spoofed fleet view.',
        bus_number: profile.bus_number
      },
      profile
    });
  }

  function handleError(error, req, res, next) {
    const srcIp = getSourceIp(req);
    logEvent({
      severity: 'ERROR',
      src_ip: srcIp,
      message: 'request_failed',
      error: error.message
    });

    if (res.headersSent) {
      next(error);
      return;
    }

    if (req.originalUrl.startsWith('/api/')) {
      res.status(500).json({ error: 'Internal Server Error' });
      return;
    }

    res.status(500).render('login', { error: 'Internal Server Error' });
  }

  return {
    requireAuth,
    requireAdmin,
    requireCustomer,
    requireSimulationAccess,
    root,
    getLogin,
    postLogin,
    postLogout,
    getDashboard,
    getAdminDashboard,
    getCustomerDashboard,
    getTicketConsole,
    getAuthSequenceConsole,
    getRansomwareConsole,
    getDnsTunnelingConsole,
    getPaymentSkimmingConsole,
    getGpsSpoofingConsole,
    getBookTicketConsole,
    getBusesConsole,
    getTicketStatusConsole,
    getPassengerTickets,
    postCustomerBooking,
    getCustomerBuses,
    getCustomerTicketStatus,
    postAuthSequence,
    postDnsTunneling,
    postRansomware,
    postPaymentSkimming,
    postGpsSpoofing,
    handleError
  };
}

function buildApp({
  database,
  logEvent = createLogger(),
  sessionSecret = process.env.SESSION_SECRET || 'change-me',
  simulationSecret = process.env.SIMULATION_SECRET || 'simulate-bta',
  simulationOptions = {}
}) {
  const app = express();
  const simulations = createSimulationManager({
    logEvent,
    ...simulationOptions
  });
  const controllers = createControllers({
    database,
    logEvent,
    simulations,
    simulationSecret
  });

  app.locals.simulations = simulations;
  app.disable('x-powered-by');
  app.set('view engine', 'ejs');
  app.set('views', path.join(__dirname, 'views'));
  app.use(express.static(path.join(__dirname, '..', 'public')));
  app.use(express.urlencoded({ extended: false }));
  app.use(express.json());
  app.use(
    session({
      secret: sessionSecret,
      resave: false,
      saveUninitialized: false,
      cookie: {
        httpOnly: true,
        maxAge: 8 * 60 * 60 * 1000,
        sameSite: 'lax'
      }
    })
  );
  app.use((req, res, next) => {
    res.locals.user = req.session.user || null;
    next();
  });
  app.use(createAccessLogMiddleware(logEvent));

  app.get('/', controllers.root);
  app.get('/login', controllers.getLogin);
  app.post('/login', controllers.postLogin);
  app.post('/logout', controllers.requireAuth, controllers.postLogout);
  app.get('/dashboard', controllers.requireAuth, controllers.getDashboard);

  app.get('/admin/dashboard', controllers.requireAuth, controllers.requireAdmin, controllers.getAdminDashboard);
  app.get(
    '/admin/passenger/tickets',
    controllers.requireAuth,
    controllers.requireAdmin,
    controllers.getTicketConsole
  );
  app.get(
    '/admin/simulations/auth-sequence',
    controllers.requireAuth,
    controllers.requireAdmin,
    controllers.getAuthSequenceConsole
  );
  app.get(
    '/admin/simulations/ransomware',
    controllers.requireAuth,
    controllers.requireAdmin,
    controllers.getRansomwareConsole
  );
  app.get(
    '/admin/simulations/dns-tunneling',
    controllers.requireAuth,
    controllers.requireAdmin,
    controllers.getDnsTunnelingConsole
  );
  app.get(
    '/admin/simulations/payment-skimming',
    controllers.requireAuth,
    controllers.requireAdmin,
    controllers.getPaymentSkimmingConsole
  );
  app.get(
    '/admin/simulations/gps-spoofing',
    controllers.requireAuth,
    controllers.requireAdmin,
    controllers.getGpsSpoofingConsole
  );

  app.get(
    '/customer/dashboard',
    controllers.requireAuth,
    controllers.requireCustomer,
    controllers.getCustomerDashboard
  );
  app.get(
    '/customer/book-ticket',
    controllers.requireAuth,
    controllers.requireCustomer,
    controllers.getBookTicketConsole
  );
  app.get('/customer/buses', controllers.requireAuth, controllers.requireCustomer, controllers.getBusesConsole);
  app.get(
    '/customer/ticket-status',
    controllers.requireAuth,
    controllers.requireCustomer,
    controllers.getTicketStatusConsole
  );

  app.get('/passenger/tickets', controllers.requireAuth, controllers.requireAdmin, controllers.getTicketConsole);
  app.get(
    '/simulations/auth-sequence',
    controllers.requireAuth,
    controllers.requireAdmin,
    controllers.getAuthSequenceConsole
  );
  app.get(
    '/simulations/ransomware',
    controllers.requireAuth,
    controllers.requireAdmin,
    controllers.getRansomwareConsole
  );
  app.get(
    '/simulations/dns-tunneling',
    controllers.requireAuth,
    controllers.requireAdmin,
    controllers.getDnsTunnelingConsole
  );
  app.get(
    '/simulations/payment-skimming',
    controllers.requireAuth,
    controllers.requireAdmin,
    controllers.getPaymentSkimmingConsole
  );
  app.get(
    '/simulations/gps-spoofing',
    controllers.requireAuth,
    controllers.requireAdmin,
    controllers.getGpsSpoofingConsole
  );

  app.get('/api/passenger/tickets', controllers.getPassengerTickets);
  app.post(
    '/api/customer/bookings',
    controllers.requireAuth,
    controllers.requireCustomer,
    controllers.postCustomerBooking
  );
  app.get(
    '/api/customer/buses',
    controllers.requireAuth,
    controllers.requireCustomer,
    controllers.getCustomerBuses
  );
  app.get(
    '/api/customer/ticket-status',
    controllers.requireAuth,
    controllers.requireCustomer,
    controllers.getCustomerTicketStatus
  );
  app.post(
    '/api/simulations/auth-sequence',
    controllers.requireSimulationAccess,
    controllers.postAuthSequence
  );
  app.post(
    '/api/simulations/ransomware',
    controllers.requireSimulationAccess,
    controllers.postRansomware
  );
  app.post(
    '/api/simulations/dns-tunneling',
    controllers.requireSimulationAccess,
    controllers.postDnsTunneling
  );
  app.post(
    '/api/simulations/payment-skimming',
    controllers.requireSimulationAccess,
    controllers.postPaymentSkimming
  );
  app.post(
    '/api/simulations/gps-spoofing',
    controllers.requireSimulationAccess,
    controllers.postGpsSpoofing
  );

  app.use(controllers.handleError);

  return app;
}

module.exports = {
  buildApp,
  createAccessLogMiddleware,
  createControllers,
  isAdminRole,
  isCustomerRole,
  resolveDashboardPath,
  severityFromStatus
};
