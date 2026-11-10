const RAW_URL = import.meta.env.VITE_API_URL || "https://scamshield-gy1b.onrender.com";
// Ensure trailing slashes are removed to prevent '//analyze/...' 404s
const API_BASE_URL = RAW_URL.replace(/\/+$/, "");

async function fetchWithTimeout(resource, options = {}) {
  // 60-second timeout allows Render free-tier cold starts to boot up without aborting
  const { timeout = 60000 } = options;
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
      throw new Error(
        "Backend server is waking up from idle (cold start). Please try again in 10-15 seconds."
      );
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
    throw new Error(errorData.detail || `Server responded with status ${response.status}`);
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
    throw new Error(errorData.detail || `Server responded with status ${response.status}`);
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
    throw new Error(errorData.detail || `Server responded with status ${response.status}`);
  }
  return await response.json();
}