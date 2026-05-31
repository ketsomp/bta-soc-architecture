const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();

function run(db, sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function onRun(error) {
      if (error) {
        reject(error);
        return;
      }

      resolve(this);
    });
  });
}

function get(db, sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (error, row) => {
      if (error) {
        reject(error);
        return;
      }

      resolve(row);
    });
  });
}

function all(db, sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (error, rows) => {
      if (error) {
        reject(error);
        return;
      }

      resolve(rows);
    });
  });
}

function close(db) {
  return new Promise((resolve, reject) => {
    db.close((error) => {
      if (error) {
        reject(error);
        return;
      }

      resolve();
    });
  });
}

async function ensureTableColumns(database, tableName, columns) {
  const existingColumns = await all(database, `PRAGMA table_info(${tableName})`);
  const existingNames = new Set(existingColumns.map((column) => column.name));

  for (const column of columns) {
    if (existingNames.has(column.name)) {
      continue;
    }

    await run(database, `ALTER TABLE ${tableName} ADD COLUMN ${column.name} ${column.type}`);
  }
}

async function seedUsers(database) {
  await run(database, 'DELETE FROM users WHERE role = ?', ['operator']);

  await run(
    database,
    `
      INSERT INTO users (username, password, role)
      VALUES (?, ?, ?)
      ON CONFLICT(username) DO UPDATE SET
        password = excluded.password,
        role = excluded.role
    `,
    ['admin', 'transit123', 'admin']
  );

  await run(
    database,
    `
      INSERT INTO users (username, password, role)
      VALUES (?, ?, ?)
      ON CONFLICT(username) DO UPDATE SET
        password = excluded.password,
        role = excluded.role
    `,
    ['customer', 'ride123', 'customer']
  );
}

async function seedTickets(database) {
  const ticketCount = await get(database, 'SELECT COUNT(*) AS count FROM tickets');

  if (ticketCount.count > 0) {
    return;
  }

  const customerUser = await get(database, 'SELECT id FROM users WHERE username = ?', ['customer']);
  const customerUserId = customerUser ? customerUser.id : null;

  await run(
    database,
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
        status,
        fare,
        issued_at,
        travel_date,
        created_by_user_id
      )
      VALUES
      (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?),
      (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?),
      (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `,
    [
      'BTA-24001',
      'Majestic - Whitefield',
      'Ananya Rao',
      '9876500011',
      'Majestic',
      'Whitefield',
      'KA-01-FM-1142',
      '12A',
      'UPI',
      'mobile_app',
      'issued',
      45.0,
      '2026-04-05T08:10:00.000Z',
      '2026-04-05T08:30:00.000Z',
      customerUserId,
      'BTA-24002',
      'Silk Board - Hebbal',
      'Rohit Kumar',
      '9876500012',
      'Silk Board',
      'Hebbal',
      'KA-01-FM-2308',
      '07C',
      'Card',
      'kiosk',
      'validated',
      35.0,
      '2026-04-05T08:14:00.000Z',
      '2026-04-05T08:40:00.000Z',
      customerUserId,
      'BTA-24003',
      'KR Market - Electronic City',
      'Farah Khan',
      '9876500013',
      'KR Market',
      'Electronic City',
      'KA-01-FM-4109',
      '18B',
      'Cash',
      'counter',
      'issued',
      50.0,
      '2026-04-05T08:20:00.000Z',
      '2026-04-05T09:00:00.000Z',
      customerUserId
    ]
  );
}

async function seedBuses(database) {
  const busCount = await get(database, 'SELECT COUNT(*) AS count FROM buses');

  if (busCount.count > 0) {
    return;
  }

  await run(
    database,
    `
      INSERT INTO buses (
        bus_number,
        route_name,
        origin_stop,
        destination_stop,
        next_departure,
        occupancy_percent,
        vehicle_status,
        driver_name
      )
      VALUES
      (?, ?, ?, ?, ?, ?, ?, ?),
      (?, ?, ?, ?, ?, ?, ?, ?),
      (?, ?, ?, ?, ?, ?, ?, ?),
      (?, ?, ?, ?, ?, ?, ?, ?)
    `,
    [
      'KA-01-FM-1142',
      'Majestic - Whitefield',
      'Majestic',
      'Whitefield',
      '2026-04-06T09:10:00.000Z',
      62,
      'in_service',
      'Shivanna',
      'KA-01-FM-2308',
      'Silk Board - Hebbal',
      'Silk Board',
      'Hebbal',
      '2026-04-06T09:20:00.000Z',
      48,
      'boarding',
      'Ramesh',
      'KA-01-FM-4109',
      'KR Market - Electronic City',
      'KR Market',
      'Electronic City',
      '2026-04-06T09:35:00.000Z',
      71,
      'in_service',
      'Naseer',
      'KA-01-FM-5520',
      'Jayanagar - Airport',
      'Jayanagar',
      'Kempegowda Airport',
      '2026-04-06T09:45:00.000Z',
      39,
      'layover',
      'Sudeep'
    ]
  );
}

async function initDb({ filename } = {}) {
  const resolvedFilename = filename || path.join(process.cwd(), 'data', 'bta-fms.sqlite');

  if (resolvedFilename !== ':memory:') {
    fs.mkdirSync(path.dirname(resolvedFilename), { recursive: true });
  }

  const database = new sqlite3.Database(resolvedFilename);

  await run(
    database,
    `
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        role TEXT NOT NULL
      )
    `
  );

  await run(
    database,
    `
      CREATE TABLE IF NOT EXISTS tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ticket_number TEXT NOT NULL UNIQUE,
        route_name TEXT NOT NULL,
        passenger_name TEXT NOT NULL,
        passenger_contact TEXT,
        source_stop TEXT,
        destination_stop TEXT,
        bus_number TEXT,
        seat_number TEXT,
        payment_mode TEXT,
        booking_channel TEXT,
        payment_terminal_id TEXT,
        status TEXT NOT NULL,
        fare REAL NOT NULL,
        issued_at TEXT NOT NULL,
        travel_date TEXT,
        created_by_user_id INTEGER
      )
    `
  );

  await run(
    database,
    `
      CREATE TABLE IF NOT EXISTS buses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bus_number TEXT NOT NULL UNIQUE,
        route_name TEXT NOT NULL,
        origin_stop TEXT NOT NULL,
        destination_stop TEXT NOT NULL,
        next_departure TEXT NOT NULL,
        occupancy_percent INTEGER NOT NULL,
        vehicle_status TEXT NOT NULL,
        driver_name TEXT NOT NULL
      )
    `
  );

  await ensureTableColumns(database, 'tickets', [
    { name: 'passenger_contact', type: 'TEXT' },
    { name: 'source_stop', type: 'TEXT' },
    { name: 'destination_stop', type: 'TEXT' },
    { name: 'bus_number', type: 'TEXT' },
    { name: 'seat_number', type: 'TEXT' },
    { name: 'payment_mode', type: 'TEXT' },
    { name: 'booking_channel', type: 'TEXT' },
    { name: 'payment_terminal_id', type: 'TEXT' },
    { name: 'travel_date', type: 'TEXT' },
    { name: 'created_by_user_id', type: 'INTEGER' }
  ]);

  await seedUsers(database);
  await seedTickets(database);
  await seedBuses(database);

  return {
    run(sql, params = []) {
      return run(database, sql, params);
    },
    get(sql, params = []) {
      return get(database, sql, params);
    },
    all(sql, params = []) {
      return all(database, sql, params);
    },
    close() {
      return close(database);
    }
  };
}

module.exports = {
  initDb
};
