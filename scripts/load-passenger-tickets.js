const endpoint = process.argv[2] || 'http://localhost:3000/api/passenger/tickets';
const totalRequests = Number(process.argv[3] || 50);
const concurrency = Number(process.argv[4] || 10);

async function executeRequest() {
  const response = await fetch(endpoint);
  return response.status;
}

async function main() {
  const startedAt = Date.now();
  let completed = 0;
  let cursor = 0;
  const statuses = {};

  async function worker() {
    while (cursor < totalRequests) {
      cursor += 1;
      const status = await executeRequest();
      statuses[status] = (statuses[status] || 0) + 1;
      completed += 1;
    }
  }

  await Promise.all(
    Array.from({ length: Math.min(concurrency, totalRequests) }, () => worker())
  );

  process.stdout.write(
    `${JSON.stringify({
      endpoint,
      total_requests: totalRequests,
      completed,
      duration_ms: Date.now() - startedAt,
      statuses
    })}\n`
  );
}

main().catch((error) => {
  process.stderr.write(`${error.message}\n`);
  process.exit(1);
});
