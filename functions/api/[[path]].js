// ============================================================
// PDF FLOW API — Cloudflare Pages Functions
// ============================================================
// File: functions/api/[[path]].js
//
// This handles all requests to /api/*
//
// Required KV bindings (set in Cloudflare Pages dashboard):
//   PDFFLOW_USERS, PDFFLOW_TOKENS, PDFFLOW_USAGE
//
// Required secrets (set in Cloudflare Pages dashboard):
//   STRIPE_SECRET, STRIPE_WEBHOOK_SECRET, RESEND_API_KEY
// ============================================================

const APP_URL = "https://pdfflow.mamonis.studio";

const PRICE_MAP = {
  standard: "price_1T2QP3AHwJIRooacsXOG1jZH",
  pro: "price_1T2QPiAHwJIRooacY2isVhcH",
  business: "price_1T2QQCAHwJIRooaclRliqcMq",
};

// Reverse map for webhook
const PRICE_TO_PLAN = {
  "price_1T2QP3AHwJIRooacsXOG1jZH": "standard",
  "price_1T2QPiAHwJIRooacY2isVhcH": "pro",
  "price_1T2QQCAHwJIRooaclRliqcMq": "business",
};

const ALLOWED_ORIGINS = [
  "https://pdfflow.mamonis.studio",
  "https://mamonis.studio",
];

function getCORS(request) {
  const origin = (request && request.headers.get("Origin")) || "";
  const allowed = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    "Access-Control-Allow-Origin": allowed,
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type,Authorization",
  };
}

function json(data, status = 200, request = null) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...getCORS(request) },
  });
}
function err(msg, status = 400) {
  return json({ error: msg }, status);
}

async function generateToken() {
  const buf = new Uint8Array(32);
  crypto.getRandomValues(buf);
  return Array.from(buf, (b) => b.toString(16).padStart(2, "0")).join("");
}
async function hashToken(token) {
  const enc = new TextEncoder().encode(token);
  const hash = await crypto.subtle.digest("SHA-256", enc);
  return Array.from(new Uint8Array(hash), (b) => b.toString(16).padStart(2, "0")).join("");
}

function usageKey(email) {
  const d = new Date();
  return `${email}:${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}`;
}

// --- Email via Resend ---
async function sendMagicLink(email, token, env) {
  const url = `${APP_URL}/api/auth/verify?token=${token}&email=${encodeURIComponent(email)}`;
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: "PDF FLOW <noreply@mamonis.studio>",
      to: [email],
      subject: "PDF FLOW — ログインリンク / Login Link",
      html: `
        <div style="font-family:-apple-system,sans-serif;max-width:480px;margin:0 auto;padding:32px">
          <div style="background:#1e3a5f;color:#fff;padding:16px 24px;border-radius:12px 12px 0 0;font-weight:700;font-size:18px">PDF FLOW</div>
          <div style="background:#fff;border:1px solid #e5e5e5;border-top:none;border-radius:0 0 12px 12px;padding:32px 24px">
            <p style="color:#333;font-size:16px;margin:0 0 8px">ログインリンク / Login Link</p>
            <p style="color:#666;font-size:14px;margin:0 0 24px">下のボタンをクリックしてログインしてください。<br>Click the button below to log in.</p>
            <a href="${url}" style="display:inline-block;background:#1e3a5f;color:#fff;padding:14px 32px;border-radius:8px;text-decoration:none;font-weight:600;font-size:14px">ログイン / Log In</a>
            <p style="color:#999;font-size:12px;margin:24px 0 0">このリンクは15分間有効です。<br>This link expires in 15 minutes.</p>
          </div>
        </div>`,
    }),
  });
  return res.ok;
}

// --- Auth: get email from session ---
async function getSessionEmail(request, env) {
  const auth = request.headers.get("Authorization");
  if (!auth || !auth.startsWith("Bearer ")) return null;
  const hashed = await hashToken(auth.slice(7));
  const stored = await env.PDFFLOW_TOKENS.get(`session:${hashed}`);
  if (!stored) return null;
  return JSON.parse(stored).email;
}

// ============================================================
// Route Handlers
// ============================================================

// POST /auth/login
async function handleLogin(request, env) {
  const { email } = await request.json();
  if (!email || !email.includes("@")) return err("Invalid email");

  const token = await generateToken();
  const hashed = await hashToken(token);
  await env.PDFFLOW_TOKENS.put(`magic:${hashed}`, JSON.stringify({ email, type: "magic" }), { expirationTtl: 900 });

  const existing = await env.PDFFLOW_USERS.get(`user:${email}`);
  if (!existing) {
    await env.PDFFLOW_USERS.put(`user:${email}`, JSON.stringify({
      email, plan: "free", createdAt: new Date().toISOString(),
      stripeCustomerId: null, stripeSubscriptionId: null,
    }));
  }

  const sent = await sendMagicLink(email, token, env);
  if (!sent) return err("Failed to send email", 500);
  return json({ ok: true });
}

// GET /auth/verify?token=...&email=...
async function handleVerify(request, env) {
  const url = new URL(request.url);
  const token = url.searchParams.get("token");
  const email = url.searchParams.get("email");
  if (!token || !email) return err("Missing params");

  const hashed = await hashToken(token);
  const stored = await env.PDFFLOW_TOKENS.get(`magic:${hashed}`);
  if (!stored) return err("Invalid or expired", 401);
  const data = JSON.parse(stored);
  if (data.email !== email) return err("Mismatch", 401);

  await env.PDFFLOW_TOKENS.delete(`magic:${hashed}`);

  const sessionToken = await generateToken();
  const sessionHashed = await hashToken(sessionToken);
  await env.PDFFLOW_TOKENS.put(`session:${sessionHashed}`, JSON.stringify({ email }), { expirationTtl: 86400 * 30 });

  return new Response(null, {
    status: 302,
    headers: { Location: `${APP_URL}/app/?session=${sessionToken}` },
  });
}

// GET /auth/me
async function handleMe(request, env) {
  const email = await getSessionEmail(request, env);
  if (!email) return err("Unauthorized", 401);

  const userStr = await env.PDFFLOW_USERS.get(`user:${email}`);
  if (!userStr) return err("Not found", 404);
  const user = JSON.parse(userStr);

  const uKey = usageKey(email);
  const usageStr = await env.PDFFLOW_USAGE.get(uKey);

  return json({
    email: user.email,
    plan: user.plan,
    usage: usageStr ? parseInt(usageStr, 10) : 0,
  });
}

// POST /auth/logout
async function handleLogout(request, env) {
  const auth = request.headers.get("Authorization");
  if (auth && auth.startsWith("Bearer ")) {
    const hashed = await hashToken(auth.slice(7));
    await env.PDFFLOW_TOKENS.delete(`session:${hashed}`);
  }
  return json({ ok: true });
}

// POST /usage/increment
async function handleUsageIncrement(request, env) {
  const email = await getSessionEmail(request, env);
  if (!email) return err("Unauthorized", 401);

  const { count } = await request.json();
  if (!count || count < 1) return err("Invalid count");

  const userStr = await env.PDFFLOW_USERS.get(`user:${email}`);
  const user = JSON.parse(userStr);
  const limits = { free: 5, standard: 100, pro: 500, business: -1 };
  const limit = limits[user.plan] ?? 5;

  const uKey = usageKey(email);
  const cur = parseInt((await env.PDFFLOW_USAGE.get(uKey)) || "0", 10);

  if (limit !== -1 && cur + count > limit) return err("Limit exceeded", 403);

  await env.PDFFLOW_USAGE.put(uKey, String(cur + count), { expirationTtl: 86400 * 35 });
  return json({ ok: true, usage: cur + count, limit });
}

// POST /stripe/create-checkout
async function handleCreateCheckout(request, env) {
  const email = await getSessionEmail(request, env);
  if (!email) return err("Unauthorized", 401);

  const { plan } = await request.json();
  const priceId = PRICE_MAP[plan];
  if (!priceId) return err("Invalid plan");

  const userStr = await env.PDFFLOW_USERS.get(`user:${email}`);
  const user = JSON.parse(userStr);
  let customerId = user.stripeCustomerId;

  if (!customerId) {
    const custRes = await fetch("https://api.stripe.com/v1/customers", {
      method: "POST",
      headers: { Authorization: `Bearer ${env.STRIPE_SECRET}`, "Content-Type": "application/x-www-form-urlencoded" },
      body: `email=${encodeURIComponent(email)}`,
    });
    const cust = await custRes.json();
    customerId = cust.id;
    user.stripeCustomerId = customerId;
    await env.PDFFLOW_USERS.put(`user:${email}`, JSON.stringify(user));
  }

  // Store reverse lookup
  await env.PDFFLOW_USERS.put(`stripe:${customerId}`, email);

  const params = new URLSearchParams({
    customer: customerId,
    mode: "subscription",
    "line_items[0][price]": priceId,
    "line_items[0][quantity]": "1",
    success_url: `${APP_URL}/app/?upgraded=true`,
    cancel_url: `${APP_URL}/app/?cancelled=true`,
    "subscription_data[metadata][email]": email,
  });

  const sRes = await fetch("https://api.stripe.com/v1/checkout/sessions", {
    method: "POST",
    headers: { Authorization: `Bearer ${env.STRIPE_SECRET}`, "Content-Type": "application/x-www-form-urlencoded" },
    body: params.toString(),
  });
  const session = await sRes.json();
  return json({ url: session.url });
}

// POST /stripe/webhook
async function handleStripeWebhook(request, env) {
  const body = await request.text();
  // TODO: verify signature with STRIPE_WEBHOOK_SECRET for production security
  let event;
  try { event = JSON.parse(body); } catch { return err("Bad payload", 400); }

  async function getEmailFromCustomer(customerId) {
    // Try reverse lookup first
    const email = await env.PDFFLOW_USERS.get(`stripe:${customerId}`);
    return email;
  }

  switch (event.type) {
    case "checkout.session.completed": {
      const session = event.data.object;
      const email = session.customer_details?.email || session.customer_email || session.metadata?.email || (await getEmailFromCustomer(session.customer));
      if (!email) break;

      const subRes = await fetch(`https://api.stripe.com/v1/subscriptions/${session.subscription}`, {
        headers: { Authorization: `Bearer ${env.STRIPE_SECRET}` },
      });
      const sub = await subRes.json();
      const priceId = sub.items?.data?.[0]?.price?.id;
      const plan = PRICE_TO_PLAN[priceId] || "standard";

      const userStr = await env.PDFFLOW_USERS.get(`user:${email}`);
      if (!userStr) break;
      const user = JSON.parse(userStr);
      user.plan = plan;
      user.stripeCustomerId = session.customer;
      user.stripeSubscriptionId = session.subscription;
      await env.PDFFLOW_USERS.put(`user:${email}`, JSON.stringify(user));
      await env.PDFFLOW_USERS.put(`stripe:${session.customer}`, email);
      break;
    }
    case "customer.subscription.updated": {
      const sub = event.data.object;
      const email = sub.metadata?.email || (await getEmailFromCustomer(sub.customer));
      if (!email) break;
      const userStr = await env.PDFFLOW_USERS.get(`user:${email}`);
      if (!userStr) break;
      const user = JSON.parse(userStr);
      const priceId = sub.items?.data?.[0]?.price?.id;
      user.plan = PRICE_TO_PLAN[priceId] || "standard";
      await env.PDFFLOW_USERS.put(`user:${email}`, JSON.stringify(user));
      break;
    }
    case "customer.subscription.deleted": {
      const sub = event.data.object;
      const email = sub.metadata?.email || (await getEmailFromCustomer(sub.customer));
      if (!email) break;
      const userStr = await env.PDFFLOW_USERS.get(`user:${email}`);
      if (!userStr) break;
      const user = JSON.parse(userStr);
      user.plan = "free";
      user.stripeSubscriptionId = null;
      await env.PDFFLOW_USERS.put(`user:${email}`, JSON.stringify(user));
      break;
    }
  }
  return json({ received: true });
}

// POST /stripe/portal
async function handlePortal(request, env) {
  const email = await getSessionEmail(request, env);
  if (!email) return err("Unauthorized", 401);

  const userStr = await env.PDFFLOW_USERS.get(`user:${email}`);
  const user = JSON.parse(userStr);
  if (!user.stripeCustomerId) return err("No subscription", 400);

  const params = new URLSearchParams({
    customer: user.stripeCustomerId,
    return_url: `${APP_URL}/app/`,
  });
  const res = await fetch("https://api.stripe.com/v1/billing_portal/sessions", {
    method: "POST",
    headers: { Authorization: `Bearer ${env.STRIPE_SECRET}`, "Content-Type": "application/x-www-form-urlencoded" },
    body: params.toString(),
  });
  const session = await res.json();
  return json({ url: session.url });
}

// ============================================================
// Router (Pages Functions onRequest)
// ============================================================
export async function onRequest(context) {
  const { request, env, params } = context;

  if (request.method === "OPTIONS") {
    return new Response(null, { headers: getCORS(request) });
  }

  // params.path is an array from [[path]].js catch-all
  const path = "/" + (params.path ? params.path.join("/") : "");

  try {
    if (path === "/auth/login" && request.method === "POST") return handleLogin(request, env);
    if (path === "/auth/verify" && request.method === "GET") return handleVerify(request, env);
    if (path === "/auth/me" && request.method === "GET") return handleMe(request, env);
    if (path === "/auth/logout" && request.method === "POST") return handleLogout(request, env);
    if (path === "/usage/increment" && request.method === "POST") return handleUsageIncrement(request, env);
    if (path === "/stripe/create-checkout" && request.method === "POST") return handleCreateCheckout(request, env);
    if (path === "/stripe/webhook" && request.method === "POST") return handleStripeWebhook(request, env);
    if (path === "/stripe/portal" && request.method === "POST") return handlePortal(request, env);
    return err("Not found", 404);
  } catch (e) {
    console.error(e);
    return err("Internal error", 500);
  }
}
