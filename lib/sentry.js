/**
 * Sentry error tracking for buglens-core.
 * Requires SENTRY_DSN environment variable.
 * Get your DSN from: https://sentry.io → Project Settings → Client Keys
 *
 * Install: npm install @sentry/node
 */

let Sentry = null;

export async function initSentry() {
  if (!process.env.SENTRY_DSN) {
    return;
  }
  try {
    const mod = await import("@sentry/node");
    Sentry = mod;
    Sentry.init({
      dsn: process.env.SENTRY_DSN,
      environment: process.env.NODE_ENV || "production",
      tracesSampleRate: 0.2,
    });
  } catch {
    // @sentry/node not installed — skip silently
  }
}

export function captureException(error, context = {}) {
  if (!Sentry) return;
  Sentry.withScope((scope) => {
    Object.entries(context).forEach(([key, value]) => scope.setExtra(key, value));
    Sentry.captureException(error);
  });
}
