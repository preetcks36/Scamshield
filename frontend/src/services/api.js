const API_BASE_URL = "http://127.0.0.1:8000";

async function fetchWithTimeout(resource, options = {}) {
  const { timeout = 8000 } = options;
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);

  try {
    const response = await fetch(resource, {
      ...options,
      signal: controller.signal,
    });
    clearTimeout(id);
    return response;
  } catch (err) {
    clearTimeout(id);
    if (err.name === "AbortError") {
      throw new Error("Connection timed out. Verify that the FastAPI backend is running on http://127.0.0.1:8000.");
    }
    throw new Error(err.message || "Failed to communicate with ScamShield API.");
  }
}

export async function analyzeMessageApi(message) {
  const response = await fetchWithTimeout(`${API_BASE_URL}/analyze/message`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message }),
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || "Failed to analyze message");
  }
  return await response.json();
}

export async function analyzeUrlApi(url) {
  const response = await fetchWithTimeout(`${API_BASE_URL}/analyze/url`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || "Failed to analyze URL");
  }
  return await response.json();
}

export async function analyzeScreenshotApi(file) {
  const formData = new FormData();
  formData.append("file", file);

  const response = await fetchWithTimeout(`${API_BASE_URL}/analyze/screenshot`, {
    method: "POST",
    body: formData,
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || "Failed to analyze screenshot");
  }
  return await response.json();
}