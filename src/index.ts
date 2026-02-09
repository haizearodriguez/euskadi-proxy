export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const origin = request.headers.get("Origin") ?? "";
    const cors = corsHeaders(origin, env.ALLOWED_ORIGINS ?? "*");
    const url = new URL(request.url);

    // Preflight
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors });
    }

    // Health
    if (request.method === "GET" && url.pathname === "/health") {
      return json(200, { ok: true }, cors);
    }

    // Router
    try {
      if (url.pathname === "/euskalmet") return await handleEuskalmet(request, env, cors);
      if (url.pathname === "/air-quality") return await handleAirQuality(request, env, cors);
      if (url.pathname === "/traffic") return await handleTraffic(request, env, cors);


      return json(404, { error: "Not found. Use /euskalmet, /air-quality, /traffic" }, cors);
    } catch (e) {
      return json(500, { error: "Worker error", message: String(e) }, cors);
    }
  },
};

type Env = {
  // Euskalmet JWT
  EUSKALMET_PRIVATE_KEY_PEM: string;
  EUSKALMET_ISSUER: string;
  EUSKALMET_EMAIL?: string;
  EUSKALMET_LOGIN_ID?: string;
  EUSKALMET_TOKEN_TTL_SECONDS?: string;

  // Euskadi base
  EUSKADI_BASE_URL?: string; // https://api.euskadi.eus (recomendado)
  ALLOWED_ORIGINS?: string;  // "*" or comma-separated
};

// ---------- Handlers ----------

async function handleEuskalmet(request: Request, env: Env, cors: Record<string, string>): Promise<Response> {
  if (request.method !== "POST") return json(405, { error: "Use POST" }, cors);

  const body = await readJson<{
    path?: string;
    method?: "GET";
  }>(request, cors);

  if ("error" in body) return  body.errorResponse;

  if (!body.data.path) return json(400, { error: "Missing body.path" }, cors);
  if ((body.data.method ?? "GET") !== "GET") return json(400, { error: "Only method=GET allowed" }, cors);

  const normalized = normalizePath(body.data.path, "/euskalmet/");
  if (!normalized.ok) return json(400, { error: normalized.error }, cors);

  const baseUrl = (env.EUSKADI_BASE_URL ?? "https://api.euskadi.eus").replace(/\/+$/, "");
  const targetUrl = baseUrl + normalized.path;

  const jwt = await signJwtRS256({
    privateKeyPem: env.EUSKALMET_PRIVATE_KEY_PEM,
    issuer: env.EUSKALMET_ISSUER,
    email: env.EUSKALMET_EMAIL,
    loginId: env.EUSKALMET_LOGIN_ID,
    ttlSeconds: Number(env.EUSKALMET_TOKEN_TTL_SECONDS ?? "300"),
  });

  return fetchAndPassThrough(targetUrl, {
    Authorization: `Bearer ${jwt}`,
    Accept: "application/json",
  }, cors);
}

async function handleAirQuality(request: Request, env: Env, cors: Record<string, string>) : Promise<Response> {
  if (request.method !== "POST") return json(405, { error: "Use POST" }, cors);

  const body = await readJson<{
    countyId?: string;
    municipalityId?: string;
    from?: string; // e.g. 2023-12-31T00:00
    to?: string;   // e.g. 2023-12-31T23:59
    lang?: string; // SPANISH
  }>(request, cors);

  if ("error" in body) return body.errorResponse;

  const { countyId, municipalityId, from, to, lang } = body.data;
  if (!countyId || !municipalityId || !from || !to) {
    return json(400, { error: "Missing countyId/municipalityId/from/to" }, cors);
  }

  const baseUrl = (env.EUSKADI_BASE_URL ?? "https://api.euskadi.eus").replace(/\/+$/, "");
  const path =
    `/air-quality/measurements/hourly/counties/${encodeURIComponent(countyId)}` +
    `/municipalities/${encodeURIComponent(municipalityId)}` +
    `/from/${encodeURIComponent(from)}` +
    `/to/${encodeURIComponent(to)}`;
  
  const u = new URL(baseUrl + path);

  console.log(u);
  
  if (lang) u.searchParams.set("lang", lang);

  return fetchAndPassThrough(u.toString(), { Accept: "application/json" }, cors);
}

async function handleTraffic(request: Request, env: Env, cors: Record<string, string>) : Promise<Response>{
  if (request.method !== "POST") return json(405, { error: "Use POST" }, cors);

  const body = await readJson<{
    year?: number;
    month?: number;
    day?: number;
    lat?: number;
    lon?: number;
    km?: number;
    page?: number;
  }>(request, cors);

  if ("error" in body) return body.errorResponse;

  const { year, month, day, lat, lon, km, page } = body.data;
  if (
    year == null || month == null || day == null ||
    lat == null || lon == null || km == null
  ) {
    return json(400, { error: "Missing year/month/day/lat/lon/km" }, cors);
  }

  const baseUrl = (env.EUSKADI_BASE_URL ?? "https://api.euskadi.eus").replace(/\/+$/, "");
  const path =
    `/traffic/v1.0/incidences/byDate/${year}/${pad2(month)}/${pad2(day)}` +
    `/byLocation/${encodeURIComponent(String(lat))}/${encodeURIComponent(String(lon))}/${encodeURIComponent(String(km))}`;

  const u = new URL(baseUrl + path);
  if (page != null) u.searchParams.set("_page", String(page));

  return fetchAndPassThrough(u.toString(), { Accept: "application/json" }, cors);
}

// ---------- Utils ----------

function pad2(n: number) {
  return String(n).padStart(2, "0");
}

async function fetchAndPassThrough(
  url: string,
  headers: Record<string, string>,
  cors: Record<string, string>,
) {
  try {
    const upstream = await fetch(url, { method: "GET", headers });
    const outHeaders = new Headers(cors);
    outHeaders.set("content-type", upstream.headers.get("content-type") ?? "application/json");
    outHeaders.set("cache-control", "private, max-age=60");
    return new Response(upstream.body, { status: upstream.status, headers: outHeaders });
  } catch (e) {
    return json(502, { error: "Upstream fetch failed", message: String(e) }, cors);
  }
}

async function readJson<T>(
  request: Request,
  cors: Record<string, string>,
): Promise<{ data: T } | { error: true; errorResponse: Response }> {
  const ct = request.headers.get("content-type") ?? "";
  if (!ct.includes("application/json")) {
    return {
      error: true,
      errorResponse: json(400, { error: "Content-Type must be application/json" }, cors),
    };
  }

  try {
    const data = (await request.json()) as T;
    return { data };
  } catch {
    return {
      error: true,
      errorResponse: json(400, { error: "Invalid JSON body" }, cors),
    };
  }
}


function corsHeaders(origin: string, allowed: string) {
  const allowAll = allowed.trim() === "*";
  const allowedSet = new Set(allowed.split(",").map((x) => x.trim()).filter(Boolean));
  const allowOrigin = allowAll ? "*" : (origin && allowedSet.has(origin) ? origin : ([...allowedSet][0] ?? origin));

  return {
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Methods": "POST,OPTIONS,GET",
    "Access-Control-Allow-Headers": "content-type",
    "Vary": "Origin",
  } as Record<string, string>;
}

function json(status: number, body: unknown, headers: Record<string, string>) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...headers, "content-type": "application/json; charset=utf-8" },
  });
}

function normalizePath(input: string, requiredPrefix: string): { ok: true; path: string } | { ok: false; error: string } {
  if (input.startsWith("http://") || input.startsWith("https://")) {
    return { ok: false, error: "Send only a path (not a full URL)" };
  }
  const p = input.startsWith("/") ? input : `/${input}`;
  if (!p.startsWith(requiredPrefix)) {
    return { ok: false, error: `Path must start with ${requiredPrefix}` };
  }
  return { ok: true, path: p };
}

// --- JWT RS256 (WebCrypto) ---
async function signJwtRS256(args: {
  privateKeyPem: string;
  issuer: string;
  email?: string;
  loginId?: string;
  ttlSeconds: number;
}) {
  if (!args.privateKeyPem) throw new Error("Missing EUSKALMET_PRIVATE_KEY_PEM");
  if (!args.issuer) throw new Error("Missing EUSKALMET_ISSUER");
  if (!args.email && !args.loginId) throw new Error("Set EUSKALMET_EMAIL or EUSKALMET_LOGIN_ID");

  const now = Math.floor(Date.now() / 1000);
  const exp = now + Math.max(30, args.ttlSeconds || 300);

  const header = { alg: "RS256", typ: "JWT" };
  const payload: any = { aud: "met01.apikey", iss: args.issuer, version: "1.0.0", iat: now, exp };
  if (args.email) payload.email = args.email;
  if (args.loginId) payload.loginId = args.loginId;

  const enc = new TextEncoder();
  const data = `${b64url(enc.encode(JSON.stringify(header)))}.${b64url(enc.encode(JSON.stringify(payload)))}`;

  const key = await importPkcs8(args.privateKeyPem);
  const sig = await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, key, enc.encode(data));
  return `${data}.${b64url(new Uint8Array(sig))}`;
}

async function importPkcs8(pem: string) {
  const b64 = pem
    .replace(/-----BEGIN PRIVATE KEY-----/g, "")
    .replace(/-----END PRIVATE KEY-----/g, "")
    .replace(/\s+/g, "");
  const der = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  return crypto.subtle.importKey(
    "pkcs8",
    der.buffer,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
}

function b64url(bytes: Uint8Array) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
