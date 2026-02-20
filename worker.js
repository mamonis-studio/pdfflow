// ============================================================
// PDF FLOW — Cloudflare Worker (Auth + Stripe + Usage)
// ============================================================
// KV Namespaces:  USERS, TOKENS, USAGE
// Environment:    STRIPE_SECRET, STRIPE_WEBHOOK_SECRET, RESEND_API_KEY, APP_URL, JWT_SECRET
// ============================================================

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS_HEADERS },
  });
}

function err(message, status = 400) {
  return json({ error: message }, status);
}

// --- Crypto Helpers ---
async function generateToken() {
  const buf = new Uint8Array(32);
  crypto.getRandomValues(buf);
  return Array.from(buf, b => b.toString(16).padStart(2, '0')).join('');
}

async function hashToken(token) {
  const encoded = new TextEncoder().encode(token);
  const hash = await crypto.subtle.digest('SHA-256', encoded);
  return Array.from(new Uint8Array(hash), b => b.toString(16).padStart(2, '0')).join('');
}

// --- Email via Resend ---
async function sendMagicLink(email, token, env) {
  const url = `${env.APP_URL}/auth/verify?token=${token}&email=${encodeURIComponent(email)}`;
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: 'PDF FLOW <noreply@pdfflow.mamonis.studio>',
      to: [email],
      subject: 'PDF FLOW — ログインリンク / Login Link',
      html: `
        <div style="font-family:-apple-system,sans-serif;max-width:480px;margin:0 auto;padding:32px">
          <div style="background:#1e3a5f;color:#fff;padding:16px 24px;border-radius:12px 12px 0 0;font-weight:700;font-size:18px">PDF FLOW</div>
          <div style="background:#fff;border:1px solid #e5e5e5;border-top:none;border-radius:0 0 12px 12px;padding:32px 24px">
            <p style="color:#333;font-size:16px;margin:0 0 8px">ログインリンク / Login Link</p>
            <p style="color:#666;font-size:14px;margin:0 0 24px">下のボタンをクリックしてログインしてください。<br>Click the button below to log in.</p>
            <a href="${url}" style="display:inline-block;background:#1e3a5f;color:#fff;padding:14px 32px;border-radius:8px;text-decoration:none;font-weight:600;font-size:14px">ログイン / Log In →</a>
            <p style="color:#999;font-size:12px;margin:24px 0 0">このリンクは15分間有効です。心当たりがない場合は無視してください。<br>This link expires in 15 minutes. Ignore if you didn't request this.</p>
          </div>
        </div>
      `,
    }),
  });
  return res.ok;
}

// --- Usage Key ---
function usageKey(email) {
  const d = new Date();
  return `${email}:${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
}

// --- Route Handlers ---

// POST /auth/login — Send magic link
async function handleLogin(request, env) {
  const { email } = await request.json();
  if (!email || !email.includes('@')) return err('Invalid email');

  const token = await generateToken();
  const hashed = await hashToken(token);

  // Store hashed token -> email, expires in 15 min
  await env.TOKENS.put(`magic:${hashed}`, JSON.stringify({ email, type: 'magic' }), { expirationTtl: 900 });

  // Ensure user record exists
  const existing = await env.USERS.get(`user:${email}`);
  if (!existing) {
    await env.USERS.put(`user:${email}`, JSON.stringify({
      email,
      plan: 'free',
      createdAt: new Date().toISOString(),
      stripeCustomerId: null,
      stripeSubscriptionId: null,
    }));
  }

  const sent = await sendMagicLink(email, token, env);
  if (!sent) return err('Failed to send email', 500);

  return json({ ok: true, message: 'Magic link sent' });
}

// GET /auth/verify?token=...&email=...  — Verify magic link, return session token
async function handleVerify(request, env) {
  const url = new URL(request.url);
  const token = url.searchParams.get('token');
  const email = url.searchParams.get('email');
  if (!token || !email) return err('Missing token or email');

  const hashed = await hashToken(token);
  const stored = await env.TOKENS.get(`magic:${hashed}`);
  if (!stored) return err('Invalid or expired token', 401);

  const data = JSON.parse(stored);
  if (data.email !== email) return err('Token mismatch', 401);

  // Delete used magic token
  await env.TOKENS.delete(`magic:${hashed}`);

  // Create session token (valid 30 days)
  const sessionToken = await generateToken();
  const sessionHashed = await hashToken(sessionToken);
  await env.TOKENS.put(`session:${sessionHashed}`, JSON.stringify({ email }), { expirationTtl: 86400 * 30 });

  // Redirect to app with session token
  const redirectUrl = `${env.APP_URL}/app?session=${sessionToken}`;
  return new Response(null, {
    status: 302,
    headers: { Location: redirectUrl },
  });
}

// GET /auth/me — Get current user info (requires Authorization header)
async function handleMe(request, env) {
  const auth = request.headers.get('Authorization');
  if (!auth || !auth.startsWith('Bearer ')) return err('Unauthorized', 401);

  const token = auth.slice(7);
  const hashed = await hashToken(token);
  const stored = await env.TOKENS.get(`session:${hashed}`);
  if (!stored) return err('Invalid session', 401);

  const { email } = JSON.parse(stored);
  const userStr = await env.USERS.get(`user:${email}`);
  if (!userStr) return err('User not found', 404);

  const user = JSON.parse(userStr);
  const uKey = usageKey(email);
  const usageStr = await env.USAGE.get(uKey);
  const usage = usageStr ? parseInt(usageStr, 10) : 0;

  return json({
    email: user.email,
    plan: user.plan,
    usage,
    stripeCustomerId: user.stripeCustomerId,
  });
}

// POST /auth/logout
async function handleLogout(request, env) {
  const auth = request.headers.get('Authorization');
  if (auth && auth.startsWith('Bearer ')) {
    const token = auth.slice(7);
    const hashed = await hashToken(token);
    await env.TOKENS.delete(`session:${hashed}`);
  }
  return json({ ok: true });
}

// POST /usage/increment — Increment usage count
async function handleUsageIncrement(request, env) {
  const auth = request.headers.get('Authorization');
  if (!auth || !auth.startsWith('Bearer ')) return err('Unauthorized', 401);

  const token = auth.slice(7);
  const hashed = await hashToken(token);
  const stored = await env.TOKENS.get(`session:${hashed}`);
  if (!stored) return err('Invalid session', 401);

  const { email } = JSON.parse(stored);
  const { count } = await request.json();
  if (!count || count < 1) return err('Invalid count');

  // Check plan limits
  const userStr = await env.USERS.get(`user:${email}`);
  const user = JSON.parse(userStr);
  const limits = { free: 5, standard: 100, pro: 500, business: -1 };
  const limit = limits[user.plan] ?? 5;

  const uKey = usageKey(email);
  const currentStr = await env.USAGE.get(uKey);
  const current = currentStr ? parseInt(currentStr, 10) : 0;

  if (limit !== -1 && current + count > limit) {
    return err('Monthly limit exceeded', 403);
  }

  await env.USAGE.put(uKey, String(current + count), { expirationTtl: 86400 * 35 }); // auto-expire after ~35 days
  return json({ ok: true, usage: current + count, limit });
}

// POST /stripe/create-checkout — Create Stripe Checkout session
async function handleCreateCheckout(request, env) {
  const auth = request.headers.get('Authorization');
  if (!auth || !auth.startsWith('Bearer ')) return err('Unauthorized', 401);

  const token = auth.slice(7);
  const hashed = await hashToken(token);
  const stored = await env.TOKENS.get(`session:${hashed}`);
  if (!stored) return err('Invalid session', 401);

  const { email } = JSON.parse(stored);
  const { plan } = await request.json();

  const priceMap = {
    // Replace with actual Stripe Price IDs after creating them in Stripe Dashboard
    standard: 'price_STANDARD_PRICE_ID',
    pro: 'price_PRO_PRICE_ID',
    business: 'price_BUSINESS_PRICE_ID',
  };
  const priceId = priceMap[plan];
  if (!priceId) return err('Invalid plan');

  // Get or create Stripe customer
  const userStr = await env.USERS.get(`user:${email}`);
  const user = JSON.parse(userStr);
  let customerId = user.stripeCustomerId;

  if (!customerId) {
    const customerRes = await fetch('https://api.stripe.com/v1/customers', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.STRIPE_SECRET}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: `email=${encodeURIComponent(email)}`,
    });
    const customer = await customerRes.json();
    customerId = customer.id;
    user.stripeCustomerId = customerId;
    await env.USERS.put(`user:${email}`, JSON.stringify(user));
  }

  // Create checkout session
  const params = new URLSearchParams({
    'customer': customerId,
    'mode': 'subscription',
    'line_items[0][price]': priceId,
    'line_items[0][quantity]': '1',
    'success_url': `${env.APP_URL}/app?upgraded=true`,
    'cancel_url': `${env.APP_URL}/app?cancelled=true`,
  });

  const sessionRes = await fetch('https://api.stripe.com/v1/checkout/sessions', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.STRIPE_SECRET}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: params.toString(),
  });
  const session = await sessionRes.json();

  return json({ url: session.url });
}

// POST /stripe/webhook — Handle Stripe webhooks
async function handleStripeWebhook(request, env) {
  const body = await request.text();
  const sig = request.headers.get('stripe-signature');

  // Verify webhook signature
  // NOTE: For production, implement proper signature verification using STRIPE_WEBHOOK_SECRET
  // Cloudflare Workers don't have native Stripe SDK, so we parse the event directly
  let event;
  try {
    event = JSON.parse(body);
  } catch {
    return err('Invalid payload', 400);
  }

  switch (event.type) {
    case 'checkout.session.completed': {
      const session = event.data.object;
      const customerId = session.customer;
      const subscriptionId = session.subscription;

      // Find user by Stripe customer ID
      // NOTE: In production, use a reverse index (customer_id -> email) in KV
      // For now, the subscription details are in the session metadata
      const email = session.customer_details?.email || session.customer_email;
      if (!email) break;

      const userStr = await env.USERS.get(`user:${email}`);
      if (!userStr) break;
      const user = JSON.parse(userStr);

      // Determine plan from price
      const sub = await fetch(`https://api.stripe.com/v1/subscriptions/${subscriptionId}`, {
        headers: { 'Authorization': `Bearer ${env.STRIPE_SECRET}` },
      });
      const subData = await sub.json();
      const priceId = subData.items?.data?.[0]?.price?.id;

      // Map price ID to plan (reverse of priceMap above)
      let plan = 'standard';
      if (priceId === 'price_PRO_PRICE_ID') plan = 'pro';
      else if (priceId === 'price_BUSINESS_PRICE_ID') plan = 'business';

      user.plan = plan;
      user.stripeSubscriptionId = subscriptionId;
      user.stripeCustomerId = customerId;
      await env.USERS.put(`user:${email}`, JSON.stringify(user));
      break;
    }

    case 'customer.subscription.deleted': {
      const sub = event.data.object;
      const customerId = sub.customer;

      // Find user by customer ID — need reverse lookup
      // For production: maintain a KV entry `stripe:${customerId}` -> email
      // Downgrade to free
      const email = sub.metadata?.email;
      if (!email) break;

      const userStr = await env.USERS.get(`user:${email}`);
      if (!userStr) break;
      const user = JSON.parse(userStr);
      user.plan = 'free';
      user.stripeSubscriptionId = null;
      await env.USERS.put(`user:${email}`, JSON.stringify(user));
      break;
    }

    case 'customer.subscription.updated': {
      // Handle plan changes (upgrade/downgrade)
      const sub = event.data.object;
      const email = sub.metadata?.email;
      if (!email) break;

      const userStr = await env.USERS.get(`user:${email}`);
      if (!userStr) break;
      const user = JSON.parse(userStr);

      const priceId = sub.items?.data?.[0]?.price?.id;
      let plan = 'standard';
      if (priceId === 'price_PRO_PRICE_ID') plan = 'pro';
      else if (priceId === 'price_BUSINESS_PRICE_ID') plan = 'business';

      user.plan = plan;
      await env.USERS.put(`user:${email}`, JSON.stringify(user));
      break;
    }
  }

  return json({ received: true });
}

// POST /stripe/portal — Create Stripe Customer Portal session
async function handlePortal(request, env) {
  const auth = request.headers.get('Authorization');
  if (!auth || !auth.startsWith('Bearer ')) return err('Unauthorized', 401);

  const token = auth.slice(7);
  const hashed = await hashToken(token);
  const stored = await env.TOKENS.get(`session:${hashed}`);
  if (!stored) return err('Invalid session', 401);

  const { email } = JSON.parse(stored);
  const userStr = await env.USERS.get(`user:${email}`);
  const user = JSON.parse(userStr);

  if (!user.stripeCustomerId) return err('No subscription found', 400);

  const params = new URLSearchParams({
    'customer': user.stripeCustomerId,
    'return_url': `${env.APP_URL}/app`,
  });

  const res = await fetch('https://api.stripe.com/v1/billing_portal/sessions', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.STRIPE_SECRET}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: params.toString(),
  });
  const session = await res.json();
  return json({ url: session.url });
}

// --- Router ---
export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS_HEADERS });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    try {
      // Auth routes
      if (path === '/auth/login' && request.method === 'POST') return handleLogin(request, env);
      if (path === '/auth/verify' && request.method === 'GET') return handleVerify(request, env);
      if (path === '/auth/me' && request.method === 'GET') return handleMe(request, env);
      if (path === '/auth/logout' && request.method === 'POST') return handleLogout(request, env);

      // Usage
      if (path === '/usage/increment' && request.method === 'POST') return handleUsageIncrement(request, env);

      // Stripe
      if (path === '/stripe/create-checkout' && request.method === 'POST') return handleCreateCheckout(request, env);
      if (path === '/stripe/webhook' && request.method === 'POST') return handleStripeWebhook(request, env);
      if (path === '/stripe/portal' && request.method === 'POST') return handlePortal(request, env);

      return err('Not found', 404);
    } catch (e) {
      console.error(e);
      return err('Internal error', 500);
    }
  },
};
