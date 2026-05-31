function createMetricCard(label, value) {
  const card = document.createElement('article');
  const metricLabel = document.createElement('p');
  const metricValue = document.createElement('p');

  card.className = 'metric-card compact';
  metricLabel.className = 'metric-label';
  metricLabel.textContent = label;
  metricValue.className = 'metric-value small';
  metricValue.textContent = String(value);
  card.append(metricLabel, metricValue);

  return card;
}

function renderJson(target, payload) {
  if (!target) {
    return;
  }

  target.textContent = JSON.stringify(payload, null, 2);
}

function renderEmptyState(target, message) {
  if (!target) {
    return;
  }

  target.innerHTML = '';
  target.className = 'result-empty';
  target.textContent = message;
}

function formDataToObject(formData) {
  const payload = {};

  for (const [name, value] of formData.entries()) {
    if (value === '') {
      continue;
    }

    payload[name] = value;
  }

  return payload;
}

function setBusy(form, busy) {
  const submitButton = form.querySelector('button[type="submit"]');

  if (!submitButton) {
    return;
  }

  submitButton.disabled = busy;
  submitButton.textContent = busy ? 'Running...' : submitButton.dataset.defaultLabel;
}

function renderTableRows(target, rows, columns, emptyColspan, emptyMessage) {
  if (!target) {
    return;
  }

  target.innerHTML = '';

  if (!rows.length) {
    const row = document.createElement('tr');
    const cell = document.createElement('td');
    cell.colSpan = emptyColspan;
    cell.className = 'table-placeholder';
    cell.textContent = emptyMessage;
    row.appendChild(cell);
    target.appendChild(row);
    return;
  }

  for (const item of rows) {
    const row = document.createElement('tr');

    for (const key of columns) {
      const cell = document.createElement('td');
      cell.textContent = String(item[key] ?? '');
      row.appendChild(cell);
    }

    target.appendChild(row);
  }
}

function renderTicketSummary(payload) {
  const summary = document.getElementById('tickets-summary');
  const tbody = document.getElementById('tickets-table-body');

  if (!summary || !tbody) {
    return;
  }

  summary.innerHTML = '';
  summary.className = 'metric-grid';
  summary.append(
    createMetricCard('Fetched At', payload.fetched_at),
    createMetricCard('Result Count', payload.total),
    createMetricCard('Status Filter', payload.filters.status),
    createMetricCard('Operator Label', payload.filters.operator_label || 'n/a')
  );

  renderTableRows(
    tbody,
    payload.tickets,
    [
      'ticket_number',
      'passenger_name',
      'route_name',
      'source_stop',
      'destination_stop',
      'bus_number',
      'seat_number',
      'status',
      'travel_date'
    ],
    9,
    'No tickets matched the current filters.'
  );
}

function renderBookingSummary(payload) {
  const summary = document.getElementById('booking-summary');

  if (!summary) {
    return;
  }

  const paymentSkimming = payload.scenario_signals?.payment_skimming || {};
  const dnsTunneling = payload.scenario_signals?.dns_tunneling || {};

  summary.innerHTML = '';
  summary.className = 'metric-grid';
  summary.append(
    createMetricCard('Status', payload.status),
    createMetricCard('Ticket Number', payload.booking.ticket_number),
    createMetricCard('Passenger', payload.booking.passenger_name),
    createMetricCard('Route', payload.booking.route_name),
    createMetricCard('Seat', payload.booking.seat_number),
    createMetricCard('Payment Mode', payload.booking.payment_mode),
    createMetricCard('Terminal ID', payload.booking.payment_terminal_id || 'n/a'),
    createMetricCard(
      'Skimming Trigger',
      paymentSkimming.triggered ? `${paymentSkimming.events_emitted} events` : 'not armed'
    ),
    createMetricCard(
      'DNS Trigger',
      dnsTunneling.triggered ? `${dnsTunneling.events_emitted} events` : 'not armed'
    )
  );
}

function renderBusSummary(payload) {
  const summary = document.getElementById('buses-summary');
  const tbody = document.getElementById('buses-table-body');

  if (!summary || !tbody) {
    return;
  }

  summary.innerHTML = '';
  summary.className = 'metric-grid';
  summary.append(
    createMetricCard('Fetched At', payload.fetched_at),
    createMetricCard('Result Count', payload.total),
    createMetricCard('Vehicle Status', payload.filters.vehicle_status),
    createMetricCard('Operator Label', payload.filters.operator_label || 'n/a'),
    createMetricCard('Spoofed Buses', payload.scenario_summary?.spoofed_count || 0)
  );

  renderTableRows(
    tbody,
    payload.buses,
    [
      'bus_number',
      'route_name',
      'displayed_location',
      'expected_location',
      'spoofed_location',
      'displayed_stop',
      'destination_stop',
      'route_integrity',
      'schedule_delta_min',
      'vehicle_status'
    ],
    10,
    'No buses matched the current filters.'
  );
}

function renderTicketStatusSummary(payload) {
  const summary = document.getElementById('ticket-status-summary');
  const tbody = document.getElementById('ticket-status-table-body');

  if (!summary || !tbody) {
    return;
  }

  summary.innerHTML = '';
  summary.className = 'metric-grid';
  summary.append(
    createMetricCard('Fetched At', payload.fetched_at),
    createMetricCard('Result Count', payload.total),
    createMetricCard('Status Filter', payload.filters.status),
    createMetricCard('Ticket Filter', payload.filters.ticket_number || 'n/a')
  );

  renderTableRows(
    tbody,
    payload.tickets,
    [
      'ticket_number',
      'passenger_name',
      'passenger_contact',
      'route_name',
      'bus_number',
      'seat_number',
      'status',
      'travel_date'
    ],
    8,
    'No tickets matched the current lookup.'
  );
}

function renderSimulationSummary(payload, mode) {
  const summary = document.getElementById('simulation-summary');

  if (!summary) {
    return;
  }

  summary.innerHTML = '';
  summary.className = 'metric-grid';

  if (mode === 'auth') {
    summary.append(
      createMetricCard('Status', payload.status),
      createMetricCard('Events Emitted', payload.events_emitted),
      createMetricCard('Username', payload.config.username),
      createMetricCard('Correlation Key', payload.config.correlation_key)
    );
    return;
  }

  if (mode === 'dns-tunneling') {
    summary.append(
      createMetricCard('Status', payload.status),
      createMetricCard('Events On Trigger', payload.events_expected),
      createMetricCard('Terminal ID', payload.profile.terminal_id),
      createMetricCard('Trigger Path', payload.trigger.path)
    );
    return;
  }

  if (mode === 'payment-skimming') {
    summary.append(
      createMetricCard('Status', payload.status),
      createMetricCard('Events On Trigger', payload.events_expected),
      createMetricCard('Terminal ID', payload.profile.terminal_id),
      createMetricCard('Trigger Path', payload.trigger.path)
    );
    return;
  }

  if (mode === 'gps-spoofing') {
    summary.append(
      createMetricCard('Status', payload.status),
      createMetricCard('Events On Trigger', payload.events_expected),
      createMetricCard('Bus Number', payload.profile.bus_number),
      createMetricCard('Trigger Path', payload.trigger.path)
    );
    return;
  }

  summary.append(
    createMetricCard('Status', payload.status),
    createMetricCard('Events Expected', payload.events_expected),
    createMetricCard('Asset Tag', payload.profile.asset_tag),
    createMetricCard('Service Name', payload.profile.service_name)
  );
}

function renderModeSuccess(mode, payload) {
  if (mode === 'tickets') {
    renderTicketSummary(payload);
    return;
  }

  if (mode === 'booking') {
    renderBookingSummary(payload);
    return;
  }

  if (mode === 'buses') {
    renderBusSummary(payload);
    return;
  }

  if (mode === 'ticket-status') {
    renderTicketStatusSummary(payload);
    return;
  }

  renderSimulationSummary(payload, mode);
}

function renderModeError(mode, message) {
  if (mode === 'tickets') {
    renderEmptyState(document.getElementById('tickets-summary'), message);
    return;
  }

  if (mode === 'booking') {
    renderEmptyState(document.getElementById('booking-summary'), message);
    return;
  }

  if (mode === 'buses') {
    renderEmptyState(document.getElementById('buses-summary'), message);
    return;
  }

  if (mode === 'ticket-status') {
    renderEmptyState(document.getElementById('ticket-status-summary'), message);
    return;
  }

  renderEmptyState(document.getElementById('simulation-summary'), message);
}

function isGetMode(mode) {
  return mode === 'tickets' || mode === 'buses' || mode === 'ticket-status';
}

async function handleConsoleSubmit(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const mode = form.dataset.consoleForm;
  const formData = new FormData(form);
  const responseTarget = document.getElementById('console-response');

  setBusy(form, true);

  try {
    let response;

    if (isGetMode(mode)) {
      const params = new URLSearchParams(formData);
      response = await fetch(`${form.action}?${params.toString()}`, {
        headers: {
          Accept: 'application/json'
        }
      });
    } else {
      response = await fetch(form.action, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json'
        },
        body: JSON.stringify(formDataToObject(formData))
      });
    }

    const payload = await response.json();
    renderJson(responseTarget, payload);

    if (!response.ok) {
      renderModeError(mode, payload.error || 'Request failed');
      return;
    }

    renderModeSuccess(mode, payload);
  } catch (error) {
    renderJson(responseTarget, { error: error.message });
    renderModeError(mode, error.message);
  } finally {
    setBusy(form, false);
  }
}

document.querySelectorAll('[data-console-form]').forEach((form) => {
  const submitButton = form.querySelector('button[type="submit"]');

  if (submitButton) {
    submitButton.dataset.defaultLabel = submitButton.textContent;
  }

  form.addEventListener('submit', handleConsoleSubmit);
});
