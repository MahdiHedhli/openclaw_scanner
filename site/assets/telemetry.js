(() => {
  const script = document.currentScript;
  const endpoint = script?.dataset?.endpoint;
  const page = script?.dataset?.page || window.location.pathname;
  if (!endpoint) return;

  const payload = JSON.stringify({
    event: "page_view",
    page
  });

  try {
    if (navigator.sendBeacon) {
      const body = new Blob([payload], { type: "application/json" });
      navigator.sendBeacon(endpoint, body);
      return;
    }
  } catch {
    // Ignore telemetry failures; the checker must not depend on metrics.
  }

  fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: payload,
    credentials: "omit",
    keepalive: true
  }).catch(() => {});
})();
