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
      if (url.pathname === "/today") return await handleToday(request, env, cors);

      if (url.pathname === "/social/state") return await handleSocialState(request, env, cors);
      if (url.pathname === "/social/status") return await handleSocialStatus(request, env, cors);
      if (url.pathname === "/social/stop") return await handleSocialStop(request, env, cors);

      return json(404, { error: "Not found. Use /euskalmet, /air-quality, /traffic, /today" }, cors);
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

  SOCIAL_ROOM: DurableObjectNamespace;
};

// ---------- Handlers ----------

async function handleEuskalmet(request: Request, env: Env, cors: Record<string, string>): Promise<Response> {
  if (request.method !== "POST") return json(405, { error: "Use POST" }, cors);

  const body = await readJson<{ path?: string; method?: "GET" }>(request, cors);
  if ("error" in body) return body.errorResponse;

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

  return fetchJsonWithEdgeCache(
    request,
    cors,
    "/euskalmet",
    body.data,
    1800, // 30 min
    targetUrl,
    {
      Authorization: `Bearer ${jwt}`,
      Accept: "application/json",
    },
  );
}

async function handleAirQuality(request: Request, env: Env, cors: Record<string, string>): Promise<Response> {
  if (request.method !== "POST") return json(405, { error: "Use POST" }, cors);

  const body = await readJson<{
    countyId?: string;
    municipalityId?: string;
    from?: string; // e.g. 2026-02-09T00:00
    to?: string;   // e.g. 2026-02-09T23:59
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
  if (lang) u.searchParams.set("lang", lang);

  return fetchJsonWithEdgeCache(
    request,
    cors,
    "/air-quality",
    body.data,
    300, // 5 min
    u.toString(),
    { Accept: "application/json" },
  );
}

async function handleTraffic(request: Request, env: Env, cors: Record<string, string>): Promise<Response> {
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
  if (year == null || month == null || day == null || lat == null || lon == null || km == null) {
    return json(400, { error: "Missing year/month/day/lat/lon/km" }, cors);
  }

  const baseUrl = (env.EUSKADI_BASE_URL ?? "https://api.euskadi.eus").replace(/\/+$/, "");
  const path =
    `/traffic/v1.0/incidences/byDate/${year}/${pad2(month)}/${pad2(day)}` +
    `/byLocation/${encodeURIComponent(String(lat))}/${encodeURIComponent(String(lon))}/${encodeURIComponent(String(km))}`;

  const u = new URL(baseUrl + path);
  if (page != null) u.searchParams.set("_page", String(page));

  return fetchJsonWithEdgeCache(
    request,
    cors,
    "/traffic",
    body.data,
    300, // 5 min
    u.toString(),
    { Accept: "application/json" },
  );
}

// ---------------- TODAY (BFF) ----------------

type TodayRequest = {
  euskalmetPath: string;
  countyId: string;
  municipalityId: string;
  from: string; // "YYYY-MM-DDT00:00"
  to: string;   // "YYYY-MM-DDT23:59"
  lang?: string;
  traffic: { year: number; month: number; day: number; lat: number; lon: number; km: number; page?: number };
};

const HOUR = 60 * 60 * 1000;

async function handleToday(request: Request, env: Env, cors: Record<string, string>) {
  if (request.method !== "POST") return json(405, { error: "Use POST" }, cors);

  const body = await readJson<TodayRequest>(request, cors);
  if ("error" in body) return body.errorResponse;

  const b = body.data;
  if (!b.euskalmetPath || !b.countyId || !b.municipalityId || !b.from || !b.to || !b.traffic) {
    return json(400, { error: "Missing fields in body" }, cors);
  }

  // Cache agregado del /today (3 min)
  const cacheKey = await makeCacheKey(request, "/today", b);
  const cached = await caches.default.match(cacheKey);
  if (cached) return withCors(cached, cors);

  const baseUrl = (env.EUSKADI_BASE_URL ?? "https://api.euskadi.eus").replace(/\/+$/, "");

  // Euskalmet URL + JWT
  const normalized = normalizePath(b.euskalmetPath, "/euskalmet/");
  if (!normalized.ok) return json(400, { error: normalized.error }, cors);
  const euskalmetUrl = baseUrl + normalized.path;

  const jwt = await signJwtRS256({
    privateKeyPem: env.EUSKALMET_PRIVATE_KEY_PEM,
    issuer: env.EUSKALMET_ISSUER,
    email: env.EUSKALMET_EMAIL,
    loginId: env.EUSKALMET_LOGIN_ID,
    ttlSeconds: Number(env.EUSKALMET_TOKEN_TTL_SECONDS ?? "300"),
  });

  // Air URL
  const airPath =
    `/air-quality/measurements/hourly/counties/${encodeURIComponent(b.countyId)}` +
    `/municipalities/${encodeURIComponent(b.municipalityId)}` +
    `/from/${encodeURIComponent(b.from)}` +
    `/to/${encodeURIComponent(b.to)}`;
  const airUrl = new URL(baseUrl + airPath);
  airUrl.searchParams.set("lang", b.lang ?? "SPANISH");

  // Traffic URL
  const tp = b.traffic;
  const trafficPath =
    `/traffic/v1.0/incidences/byDate/${tp.year}/${pad2(tp.month)}/${pad2(tp.day)}` +
    `/byLocation/${encodeURIComponent(String(tp.lat))}/${encodeURIComponent(String(tp.lon))}/${encodeURIComponent(String(tp.km))}`;
  const trafficUrl = new URL(baseUrl + trafficPath);
  trafficUrl.searchParams.set("_page", String(tp.page ?? 1));

  // Fetch paralelo aprovechando cache por fuente + decoder robusto
  const [forecastResp, airResp, trafficResp] = await Promise.all([
    fetchJsonWithEdgeCache(
      request, cors, "/euskalmet", { path: b.euskalmetPath, method: "GET" }, 1800,
      euskalmetUrl,
      { Authorization: `Bearer ${jwt}`, Accept: "application/json" },
    ),
    fetchJsonWithEdgeCache(
      request, cors, "/air-quality",
      { countyId: b.countyId, municipalityId: b.municipalityId, from: b.from, to: b.to, lang: b.lang ?? "SPANISH" },
      300,
      airUrl.toString(),
      { Accept: "application/json" },
    ),
    fetchJsonWithEdgeCache(
      request, cors, "/traffic",
      { year: tp.year, month: tp.month, day: tp.day, lat: tp.lat, lon: tp.lon, km: tp.km, page: tp.page ?? 1 },
      300,
      trafficUrl.toString(),
      { Accept: "application/json" },
    ),
  ]);

  const forecastRaw = await forecastResp.json();
  const airRaw = await airResp.json();
  const trafficRaw = await trafficResp.json();

  // Normaliza + timeline
  const air = normalizeAirHourly(airRaw);
  const traffic = summarizeTraffic(trafficRaw);
  const timeline = buildTimeline24h(b.from, air, traffic);

  // VM para el mock
  const vm = buildTodayVM(forecastRaw, timeline);

  const resp = new Response(JSON.stringify(vm), {
    status: 200,
    headers: { ...cors, "content-type": "application/json; charset=utf-8" },
  });

  // Cachea una COPIA (/today = 3 min) — sin usar ttlSeconds aquí
  const cacheResp = resp.clone();
  cacheResp.headers.set("Cache-Control", "public, max-age=0, s-maxage=180");
  await caches.default.put(cacheKey, cacheResp);

  return resp;
}

function normalizeAirHourly(raw: unknown) {
  const arr = Array.isArray(raw) ? raw : [];
  const byHour = new Map<number, { t: number; o3?: number; quality?: string; confidence: "high" | "low" }>();

  for (const item of arr as any[]) {
    const ms = Date.parse(item.date);
    const t = Math.floor(ms / HOUR) * HOUR;

    const st = item.station?.[0];
    const meas = st?.measurements ?? [];

    const o3Valid = meas.find((m: any) => m.name === "O3" && Number(m.value) > 0);
    const hasData = !!o3Valid && st?.airQualityStation && st.airQualityStation !== "Sin datos";

    byHour.set(t, {
      t,
      o3: hasData ? Number(o3Valid.value) : undefined,
      quality: hasData ? st.airQualityStation : undefined,
      confidence: hasData ? "high" : "low",
    });
  }

  return [...byHour.values()].sort((a, b) => a.t - b.t);
}

function summarizeTraffic(raw: any) {
  const incidences = raw?.incidences ?? [];
  const rank: any = { Baja: 1, Media: 2, Alta: 3 };

  let maxLevel: string | undefined;
  for (const i of incidences) {
    const lvl = i.incidenceLevel;
    if (!maxLevel || (rank[lvl] ?? 0) > (rank[maxLevel] ?? 0)) maxLevel = lvl;
  }

  return { nearbyCount: incidences.length, maxLevel };
}

function buildTimeline24h(fromLocalLike: string, air: any[], traffic: any) {
  // MVP: slots 24h en UTC (suficiente para UI; luego lo ajustamos a Europe/Madrid si quieres)
  const date = fromLocalLike.slice(0, 10); // YYYY-MM-DD
  const start = Date.parse(date + "T00:00:00Z");

  const airMap = new Map<number, any>(air.map((x) => [x.t, x]));

  return Array.from({ length: 24 }, (_, k) => {
    const t = start + k * HOUR;
    return {
      t,
      air: airMap.get(t) ?? { confidence: "low" as const },
      traffic,
    };
  });
}

// ---- Score + VM ----

function qualityToAirScore(q?: string, confidence?: "high" | "low") {
  if (confidence === "low") return 55;
  switch ((q ?? "").toLowerCase()) {
    case "muy buena": return 90;
    case "buena": return 78;
    case "admisible": return 60;
    case "mala": return 35;
    case "muy mala": return 20;
    default: return 70;
  }
}

function trafficToScore(t: { nearbyCount: number; maxLevel?: string }) {
  if (!t.nearbyCount) return 92;
  if (t.maxLevel === "Alta") return 55;
  if (t.maxLevel === "Media") return 75;
  return 82;
}

function computeHourScore(hour: any, meteoScore: number) {
  const airScore = qualityToAirScore(hour.air?.quality, hour.air?.confidence);
  const trafficScore = trafficToScore(hour.traffic);
  const noiseScore = 50; // MVP (sin capa ruido aún)
  const score = Math.round(0.45 * airScore + 0.25 * meteoScore + 0.20 * trafficScore + 0.10 * noiseScore);
  return { score, components: { air: airScore, meteo: meteoScore, traffic: trafficScore, noise: noiseScore } };
}

function pickBestWindow2h(scored: { t: number; score: number }[]) {
  let best = { start: scored[0]?.t ?? 0, end: (scored[0]?.t ?? 0) + 2 * HOUR, avg: -1 };
  for (let i = 0; i < scored.length - 1; i++) {
    const avg = (scored[i].score + scored[i + 1].score) / 2;
    if (avg > best.avg) best = { start: scored[i].t, end: scored[i + 1].t + HOUR, avg };
  }
  return best;
}

function fmtHHMM(t: number) {
  const d = new Date(t);
  const hh = String(d.getUTCHours()).padStart(2, "0");
  const mm = String(d.getUTCMinutes()).padStart(2, "0");
  return `${hh}:${mm}`;
}

function buildTodayVM(forecast: any, timeline: any[]) {
  const forecastText = forecast?.forecastText?.SPANISH ?? "";
  const meteoScore = forecastText.toLowerCase().includes("lluvia") ? 62 : 75;

  const scored = timeline.map((h: any) => {
    const r = computeHourScore(h, meteoScore);
    return { t: h.t, score: r.score, components: r.components, air: h.air, traffic: h.traffic };
  });

  const best = pickBestWindow2h(scored);
  const bestWindow = `${fmtHHMM(best.start)}–${fmtHHMM(best.end)}`;

  // “Ahora / +3h / +6h”
  const now = Date.now();
  const baseIdx = Math.min(23, Math.max(0, Math.floor((now - scored[0].t) / HOUR)));
  const w0 = scored[baseIdx];
  const w3 = scored[Math.min(23, baseIdx + 3)];
  const w6 = scored[Math.min(23, baseIdx + 6)];

  const statusFromScore = (s: number) => (s >= 80 ? "best" : s >= 60 ? "ok" : "avoid");

  const headlineScore = Math.max(w0?.score ?? 0, Math.round(best.avg));
  const badges: string[] = [];
  if ((w0?.components.air ?? 0) >= 75) badges.push("Aire limpio");
  if ((w0?.traffic?.nearbyCount ?? 0) === 0) badges.push("Sin incidencias");
  if (!forecastText.toLowerCase().includes("lluvia") || meteoScore >= 70) badges.push("Baja lluvia");

  const recs = [
    { type: "walk", text: `Caminar: ${bestWindow} (zona recomendada)` },
    { type: "run", text: `Correr: ${fmtHHMM(best.start + HOUR)}–${fmtHHMM(best.end)} (si quieres aire mejor)` },
    { type: "avoid", text: `Evitar: 18:00–20:00 (peor aire + más tráfico)` },
  ];

  const explainComponents = scored[baseIdx]?.components ?? { air: 70, meteo: meteoScore, traffic: 80, noise: 50 };

  return {
    date: new Date(timeline[0].t).toISOString().slice(0, 10),
    headline: { score: headlineScore, bestWindow, summary: "Buen momento para salir" },
    badges,
    recommendations: recs,
    windows: [
      { label: "Ahora", score: w0?.score ?? 0, status: statusFromScore(w0?.score ?? 0) },
      { label: "+3h", score: w3?.score ?? 0, status: statusFromScore(w3?.score ?? 0) },
      { label: "+6h", score: w6?.score ?? 0, status: statusFromScore(w6?.score ?? 0) },
    ],
    explain: {
      components: explainComponents,
      text: "El aire está mejor y hay pocas incidencias.",
    },
    timeline,
    forecast,
  };
}

// ---------- Utils ----------

function pad2(n: number) {
  return String(n).padStart(2, "0");
}

// IMPORTANT: clona para no reusar streams de body
function withCors(resp: Response, cors: Record<string, string>) {
  const headers = new Headers(resp.headers);
  for (const [k, v] of Object.entries(cors)) headers.set(k, v);
  return new Response(resp.body, { status: resp.status, headers });
}

async function sha256Hex(input: string) {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  const arr = Array.from(new Uint8Array(digest));
  return arr.map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Para cachear por body (Cloudflare cache key debe ser Request)
async function makeCacheKey(request: Request, path: string, body: unknown) {
  const url = new URL(request.url);
  url.pathname = path;
  url.searchParams.set("k", await sha256Hex(JSON.stringify(body)));
  return new Request(url.toString(), { method: "GET" });
}

// Fetch JSON robusto: charset -> UTF-8 -> fallback latin1
async function fetchJsonSmart(url: string, headers: Record<string, string>) {
  const r = await fetch(url, { method: "GET", headers });
  const buf = await r.arrayBuffer();
  const ct = (r.headers.get("content-type") ?? "").toLowerCase();
  const charset = ct.match(/charset=([^;]+)/)?.[1]?.trim();

  const tryDecode = (enc: string) =>
    new TextDecoder(enc as any, { fatal: false, ignoreBOM: true }).decode(buf);

  let txt = "";
  if (charset) {
    try {
      txt = tryDecode(charset);
      return { status: r.status, json: JSON.parse(txt) };
    } catch {
      // fallback
    }
  }

  txt = tryDecode("utf-8");
  const looksBroken = txt.includes("d�a") || (txt.match(/\uFFFD/g)?.length ?? 0) > 2;

  if (looksBroken) {
    try {
      const txtLatin = tryDecode("iso-8859-1");
      return { status: r.status, json: JSON.parse(txtLatin) };
    } catch {
      // fallback
    }
  }

  return { status: r.status, json: JSON.parse(txt) };
}

async function fetchJsonWithEdgeCache(
  request: Request,
  cors: Record<string, string>,
  cachePath: string,
  cacheBody: unknown,
  ttlSeconds: number,
  url: string,
  headers: Record<string, string>,
) {
  const cacheKey = await makeCacheKey(request, cachePath, cacheBody);
  const cached = await caches.default.match(cacheKey);
  if (cached) return withCors(cached, cors);

  const { status, json: payload } = await fetchJsonSmart(url, headers);

  const resp = new Response(JSON.stringify(payload), {
    status,
    headers: { ...cors, "content-type": "application/json; charset=utf-8" },
  });

  // Cachea una COPIA (sin reusar body)
  const cacheResp = resp.clone();
  cacheResp.headers.set("Cache-Control", `public, max-age=0, s-maxage=${Math.max(30, ttlSeconds)}`);
  await caches.default.put(cacheKey, cacheResp);

  return resp;
}

async function readJson<T>(
  request: Request,
  cors: Record<string, string>,
): Promise<{ data: T } | { error: true; errorResponse: Response }> {
  const ct = request.headers.get("content-type") ?? "";
  if (!ct.includes("application/json")) {
    return { error: true, errorResponse: json(400, { error: "Content-Type must be application/json" }, cors) };
  }

  try {
    const data = (await request.json()) as T;
    return { data };
  } catch {
    return { error: true, errorResponse: json(400, { error: "Invalid JSON body" }, cors) };
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

// ---------------- SOCIAL (online, efímero) ----------------

type SocialStatus = "walking" | "later";

type SocialStatusUpsertRequest = {
  groupId: string;      // ej: "bilbao" o municipioId
  userId: string;       // id local pseudoaleatorio (front lo genera y guarda)
  name: string;         // "María"
  status: SocialStatus; // "walking" | "later"
  untilMs: number;      // epoch ms, caducidad (ej: ahora + 60 min)
};

type SocialStopRequest = {
  groupId: string;
  userId: string;
};

async function handleSocialState(request: Request, env: Env, cors: Record<string, string>) {
  if (request.method !== "GET") return json(405, { error: "Use GET" }, cors);
  const url = new URL(request.url);
  const groupId = url.searchParams.get("groupId") ?? "default";

  const id = env.SOCIAL_ROOM.idFromName(groupId);
  const stub = env.SOCIAL_ROOM.get(id);

  const r = await stub.fetch("https://do/social/state");
  return withCors(r, cors);
}

async function handleSocialStatus(request: Request, env: Env, cors: Record<string, string>) {
  if (request.method !== "POST") return json(405, { error: "Use POST" }, cors);

  const body = await readJson<SocialStatusUpsertRequest>(request, cors);
  if ("error" in body) return body.errorResponse;

  const b = body.data;
  if (!b.groupId || !b.userId || !b.name || !b.status || !b.untilMs) {
    return json(400, { error: "Missing groupId/userId/name/status/untilMs" }, cors);
  }

  const id = env.SOCIAL_ROOM.idFromName(b.groupId);
  const stub = env.SOCIAL_ROOM.get(id);

  const r = await stub.fetch("https://do/social/status", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(b),
  });

  return withCors(r, cors);
}

async function handleSocialStop(request: Request, env: Env, cors: Record<string, string>) {
  if (request.method !== "POST") return json(405, { error: "Use POST" }, cors);

  const body = await readJson<SocialStopRequest>(request, cors);
  if ("error" in body) return body.errorResponse;

  const b = body.data;
  if (!b.groupId || !b.userId) return json(400, { error: "Missing groupId/userId" }, cors);

  const id = env.SOCIAL_ROOM.idFromName(b.groupId);
  const stub = env.SOCIAL_ROOM.get(id);

  const r = await stub.fetch("https://do/social/stop", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(b),
  });

  return withCors(r, cors);
}

type StoredUser = {
  userId: string;
  name: string;
  status: SocialStatus;
  untilMs: number;
  updatedAtMs: number;
};

export class SocialRoom {
  state: DurableObjectState;

  constructor(state: DurableObjectState) {
    this.state = state;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/social/state" && request.method === "GET") {
      await this.cleanupExpired();
      const users = await this.getAllUsers();
      // devolver solo activos y ordenados por "walking primero"
      const now = Date.now();
      const active = users
        .filter((u) => u.untilMs > now)
        .sort((a, b) => (a.status === b.status ? b.updatedAtMs - a.updatedAtMs : a.status === "walking" ? -1 : 1));
      return new Response(JSON.stringify({ now, active }), {
        status: 200,
        headers: { "content-type": "application/json; charset=utf-8" },
      });
    }

    if (url.pathname === "/social/status" && request.method === "POST") {
      const b = (await request.json()) as SocialStatusUpsertRequest;

      const key = `u:${b.userId}`;
      const value: StoredUser = {
        userId: b.userId,
        name: b.name,
        status: b.status,
        untilMs: b.untilMs,
        updatedAtMs: Date.now(),
      };

      await this.state.storage.put(key, value);
      await this.cleanupExpired();

      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json; charset=utf-8" },
      });
    }

    if (url.pathname === "/social/stop" && request.method === "POST") {
      const b = (await request.json()) as SocialStopRequest;
      await this.state.storage.delete(`u:${b.userId}`);
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json; charset=utf-8" },
      });
    }

    return new Response("Not found", { status: 404 });
  }

  private async getAllUsers(): Promise<StoredUser[]> {
    const list = await this.state.storage.list<StoredUser>({ prefix: "u:" });
    return Array.from(list.values());
  }

  private async cleanupExpired() {
    const now = Date.now();
    const list = await this.state.storage.list<StoredUser>({ prefix: "u:" });
    const deletes: string[] = [];
    for (const [k, v] of list.entries()) {
      if (!v?.untilMs || v.untilMs <= now) deletes.push(k);
    }
    if (deletes.length) await this.state.storage.delete(deletes);
  }
}

