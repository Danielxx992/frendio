import { DurableObject } from "cloudflare:workers";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Max-Age": "86400"
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" }
  });
}

function makeHash(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function authenticateGuest(request, env) {
  const authorization = request.headers.get("Authorization") || "";
  if (!authorization.startsWith("Bearer ")) {
    return { response: json({ success: false, message: "Session token is required" }, 401) };
  }

  const token = authorization.slice(7).trim();
  if (!/^[a-f0-9]{64}$/i.test(token)) {
    return { response: json({ success: false, message: "Invalid session token" }, 401) };
  }

  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(token)
  );
  const tokenHash = makeHash(digest);

  const guest = await env.DB.prepare(`
    SELECT id, display_name, gender, country_code, expires_at, status
    FROM guest_sessions
    WHERE token_hash = ?
    LIMIT 1
  `).bind(tokenHash).first();

  if (!guest || guest.status !== "active") {
    return { response: json({ success: false, message: "Guest session is inactive or not found" }, 401) };
  }

  if (guest.expires_at <= Math.floor(Date.now() / 1000)) {
    await env.DB.prepare(
      "UPDATE guest_sessions SET status = 'expired' WHERE id = ?"
    ).bind(guest.id).run();
    return { response: json({ success: false, message: "Guest session expired" }, 401) };
  }

  await env.DB.prepare(
    "UPDATE guest_sessions SET last_seen_at = unixepoch() WHERE id = ?"
  ).bind(guest.id).run();

  return { guest };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    if (url.pathname === "/") {
      return json({ name: "Frendio API", status: "running", version: "3.0.0" });
    }

    if (url.pathname === "/api/health") {
      return json({ success: true, message: "Frendio backend is running" });
    }

    if (url.pathname === "/api/db-check") {
      try {
        const result = await env.DB.prepare(
          "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE '_cf_%'"
        ).all();
        return json({
          success: true,
          database: "connected",
          application_tables: result.results.length,
          tables: result.results.map(row => row.name)
        });
      } catch (error) {
        console.error("DB check failed:", error);
        return json({ success: false, message: "Database connection failed" }, 500);
      }
    }

    if (url.pathname === "/api/guest/create") {
      if (request.method !== "POST") {
        return json({ success: false, message: "Use POST method" }, 405);
      }

      try {
        const body = await request.json();

        if (body.age_confirmed !== true) {
          return json({ success: false, message: "You must confirm that you are 18 or older" }, 400);
        }
        if (body.terms_accepted !== true) {
          return json({ success: false, message: "You must accept the Terms and Privacy Policy" }, 400);
        }

        const gender = String(body.gender || "prefer_not_to_say");
        if (!["male", "female", "prefer_not_to_say"].includes(gender)) {
          return json({ success: false, message: "Invalid gender" }, 400);
        }

        const country = String(body.country_code || "").toUpperCase();
        if (country && !/^[A-Z]{2}$/.test(country)) {
          return json({ success: false, message: "Invalid country code" }, 400);
        }

        let displayName = String(body.display_name || "").trim();
        if (!displayName) displayName = "Guest-" + crypto.randomUUID().slice(0, 6);
        if (displayName.length < 2 || displayName.length > 30) {
          return json({ success: false, message: "Nickname must be 2 to 30 characters" }, 400);
        }

        const randomBytes = crypto.getRandomValues(new Uint8Array(32));
        const sessionToken = Array.from(randomBytes)
          .map(byte => byte.toString(16).padStart(2, "0"))
          .join("");

        const digest = await crypto.subtle.digest(
          "SHA-256",
          new TextEncoder().encode(sessionToken)
        );
        const tokenHash = makeHash(digest);
        const guestId = crypto.randomUUID();
        const expiresAt = Math.floor(Date.now() / 1000) + 86400;

        await env.DB.prepare(`
          INSERT INTO guest_sessions (
            id, token_hash, display_name, gender, country_code,
            age_confirmed, created_at, expires_at, last_seen_at, status
          )
          VALUES (?, ?, ?, ?, ?, 1, unixepoch(), ?, unixepoch(), 'active')
        `).bind(
          guestId, tokenHash, displayName, gender, country || null, expiresAt
        ).run();

        return json({
          success: true,
          message: "Guest session created successfully",
          guest: {
            id: guestId,
            display_name: displayName,
            gender,
            country_code: country || null
          },
          session_token: sessionToken,
          expires_at: expiresAt
        }, 201);
      } catch (error) {
        console.error("Guest creation error:", error);
        return json({ success: false, message: "Could not create guest session" }, 500);
      }
    }

    if (url.pathname === "/api/guest/verify") {
      if (request.method !== "GET") {
        return json({ success: false, message: "Use GET method" }, 405);
      }
      try {
        const auth = await authenticateGuest(request, env);
        if (auth.response) return auth.response;
        return json({
          success: true,
          message: "Guest session verified",
          guest: {
            id: auth.guest.id,
            display_name: auth.guest.display_name,
            gender: auth.guest.gender,
            country_code: auth.guest.country_code
          },
          expires_at: auth.guest.expires_at
        });
      } catch (error) {
        console.error("Guest verification error:", error);
        return json({ success: false, message: "Could not verify guest session" }, 500);
      }
    }

    if (url.pathname === "/api/match/join") {
      if (request.method !== "POST") {
        return json({ success: false, message: "Use POST method" }, 405);
      }
      try {
        const auth = await authenticateGuest(request, env);
        if (auth.response) return auth.response;

        const stub = env.MATCHMAKER.get(
          env.MATCHMAKER.idFromName("global-matchmaking")
        );
        const response = await stub.fetch("https://matchmaker/join", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ guest: auth.guest })
        });
        return new Response(response.body, {
          status: response.status,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      } catch (error) {
        console.error("Match join error:", error);
        return json({ success: false, message: "Could not join matching queue" }, 500);
      }
    }

    if (url.pathname === "/api/match/status") {
      if (request.method !== "GET") {
        return json({ success: false, message: "Use GET method" }, 405);
      }
      try {
        const auth = await authenticateGuest(request, env);
        if (auth.response) return auth.response;

        const stub = env.MATCHMAKER.get(
          env.MATCHMAKER.idFromName("global-matchmaking")
        );
        const response = await stub.fetch(
          "https://matchmaker/status?guest_id=" + encodeURIComponent(auth.guest.id)
        );
        return new Response(response.body, {
          status: response.status,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      } catch (error) {
        console.error("Match status error:", error);
        return json({ success: false, message: "Could not check match status" }, 500);
      }
    }

    if (url.pathname === "/api/match/leave") {
      if (request.method !== "POST") {
        return json({ success: false, message: "Use POST method" }, 405);
      }
      try {
        const auth = await authenticateGuest(request, env);
        if (auth.response) return auth.response;

        const stub = env.MATCHMAKER.get(
          env.MATCHMAKER.idFromName("global-matchmaking")
        );
        const response = await stub.fetch("https://matchmaker/leave", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ guest_id: auth.guest.id })
        });
        return new Response(response.body, {
          status: response.status,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      } catch (error) {
        console.error("Match leave error:", error);
        return json({ success: false, message: "Could not leave matching queue" }, 500);
      }
    }

    return json({ success: false, message: "API endpoint not found" }, 404);
  }
};

export class Matchmaker extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.ctx = ctx;
  }

  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === "/join" && request.method === "POST") {
      const body = await request.json();
      const guest = body.guest;

      if (!guest || !guest.id) {
        return Response.json({ success: false, message: "Guest is required" }, { status: 400 });
      }

      const now = Date.now();
      let waiting = (await this.ctx.storage.get("waiting")) || [];
      let matches = (await this.ctx.storage.get("matches")) || {};

      waiting = waiting.filter(item => now - item.joined_at < 120000);

      if (matches[guest.id]) {
        return Response.json({ success: true, status: "matched", match: matches[guest.id] });
      }

      if (!waiting.some(item => item.id === guest.id)) {
        const partnerIndex = waiting.findIndex(item => item.id !== guest.id);

        if (partnerIndex >= 0) {
          const partner = waiting.splice(partnerIndex, 1)[0];
          const matchId = crypto.randomUUID();

          const guestMatch = {
            match_id: matchId,
            partner: {
              id: partner.id,
              display_name: partner.display_name,
              country_code: partner.country_code
            }
          };
          const partnerMatch = {
            match_id: matchId,
            partner: {
              id: guest.id,
              display_name: guest.display_name,
              country_code: guest.country_code
            }
          };

          matches[guest.id] = guestMatch;
          matches[partner.id] = partnerMatch;
          await this.ctx.storage.put("matches", matches);
          await this.ctx.storage.put("waiting", waiting);

          return Response.json({ success: true, status: "matched", match: guestMatch });
        }

        waiting.push({
          id: guest.id,
          display_name: guest.display_name,
          country_code: guest.country_code,
          joined_at: now
        });
      }

      await this.ctx.storage.put("waiting", waiting);
      await this.ctx.storage.put("matches", matches);

      return Response.json({
        success: true,
        status: "waiting",
        message: "Searching for a stranger"
      });
    }

    if (url.pathname === "/status" && request.method === "GET") {
      const guestId = url.searchParams.get("guest_id");
      if (!guestId) {
        return Response.json({ success: false, message: "Guest ID is required" }, { status: 400 });
      }

      const matches = (await this.ctx.storage.get("matches")) || {};
      if (matches[guestId]) {
        return Response.json({ success: true, status: "matched", match: matches[guestId] });
      }

      const waiting = (await this.ctx.storage.get("waiting")) || [];
      if (waiting.some(item => item.id === guestId)) {
        return Response.json({ success: true, status: "waiting" });
      }

      return Response.json({ success: true, status: "not_in_queue" });
    }

    if (url.pathname === "/leave" && request.method === "POST") {
      const body = await request.json();
      const guestId = body.guest_id;

      if (!guestId) {
        return Response.json({ success: false, message: "Guest ID is required" }, { status: 400 });
      }

      let waiting = (await this.ctx.storage.get("waiting")) || [];
      let matches = (await this.ctx.storage.get("matches")) || {};
      waiting = waiting.filter(item => item.id !== guestId);

      const ownMatch = matches[guestId];
      if (ownMatch) {
        const partnerId = Object.keys(matches).find(
          id => id !== guestId && matches[id].match_id === ownMatch.match_id
        );
        if (partnerId) delete matches[partnerId];
        delete matches[guestId];
      }

      await this.ctx.storage.put("waiting", waiting);
      await this.ctx.storage.put("matches", matches);

      return Response.json({ success: true, message: "You left matching" });
    }
    // GitHub deployment test - Frendio

    return Response.json({ success: false, message: "Not found" }, { status: 404 });
  }
}
