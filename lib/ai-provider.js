/**
 * BugLens AI Provider
 *
 * Unified interface over multiple AI backends:
 *   - PRO users  → Primary model (high-quality, paid)
 *   - FREE users → OpenRouter qwen/qwen3-coder:free
 *   - Fallback   → OpenRouter google/gemma-4-31b-it:free
 *
 * Both adapters expose the same interface:
 *   model.generateContent(prompt) → { response: { text: () => string } }
 *
 * RULE: Never log or expose model names to users. Use generic log labels only.
 */

import { GoogleGenerativeAI } from "@google/generative-ai";
import OpenAI from "openai";

// ── System instruction (shared across all providers) ─────────────────────────
const SYSTEM_INSTRUCTION =
  "You are a senior tech lead and security auditor. Your goal is high-precision code reviews.\n" +
  "Rules:\n" +
  "1. Review only real issues that are directly supported by the diff.\n" +
  "2. Prioritize security, correctness, and reliability over style.\n" +
  "3. If no actionable issue exists, respond exactly with NO_ISSUES.\n" +
  "4. Include a valid line number in every finding.\n" +
  "5. Code suggestions must be syntactically correct and directly fix the issue.\n" +
  "6. Never hallucinate dependencies or APIs.";

// ── OpenRouter free model chain ───────────────────────────────────────────────
const OPENROUTER_FREE_MODELS = [
  "google/gemma-4-31b-it:free",   // Quality score 65, 262K context, Vision+Tools, $0
];

// ── Lazy-initialized clients ──────────────────────────────────────────────────
let _geminiClient = null;
let _openRouterClient = null;

function getGeminiClient() {
  if (!_geminiClient) {
    if (!process.env.GEMINI_API_KEY) throw new Error("GEMINI_API_KEY not set");
    _geminiClient = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
  }
  return _geminiClient;
}

function getOpenRouterClient() {
  if (!_openRouterClient) {
    if (!process.env.OPENROUTER_API_KEY) return null;
    _openRouterClient = new OpenAI({
      baseURL: "https://openrouter.ai/api/v1",
      apiKey: process.env.OPENROUTER_API_KEY,
      defaultHeaders: {
        "HTTP-Referer": "https://buglens.app",
        "X-Title": "BugLens",
      },
    });
  }
  return _openRouterClient;
}

// ── Rate-limit / down detection ───────────────────────────────────────────────
function isRetryableError(err) {
  const status = err?.status ?? err?.response?.status;
  if (status === 429 || status === 503 || status === 502) return true;
  const msg = (err?.message ?? "").toLowerCase();
  return msg.includes("rate limit") || msg.includes("unavailable") || msg.includes("overloaded");
}

// ── Adapters ──────────────────────────────────────────────────────────────────

/**
 * Wraps Gemini SDK into the shared interface.
 */
function createGeminiAdapter() {
  const geminiModel = getGeminiClient().getGenerativeModel({
    model: "gemini-2.5-flash",
    systemInstruction: SYSTEM_INSTRUCTION,
  });

  return {
    _label: "primary",
    async generateContent(prompt) {
      // Gemini SDK already returns { response: { text() } } — pass through directly
      return geminiModel.generateContent(prompt);
    },
  };
}

/**
 * Wraps OpenRouter (OpenAI-compatible) into the shared interface.
 */
function createOpenRouterAdapter(modelId, label) {
  const client = getOpenRouterClient();
  if (!client) return null;

  return {
    _label: label,
    async generateContent(prompt) {
      const completion = await client.chat.completions.create({
        model: modelId,
        messages: [
          { role: "system", content: SYSTEM_INSTRUCTION },
          { role: "user", content: prompt },
        ],
        temperature: 0.1,
        max_tokens: 4096,
      });

      const text = completion.choices?.[0]?.message?.content?.trim() ?? "";
      return {
        response: { text: () => text },
      };
    },
  };
}

/**
 * Wraps an adapter with automatic fallback to a list of next adapters.
 * On a retryable error (429, 503), tries the next adapter in the chain.
 */
function withFallback(primary, fallbacks = []) {
  const chain = [primary, ...fallbacks].filter(Boolean);

  return {
    async generateContent(prompt) {
      let lastError;

      for (const adapter of chain) {
        try {
          const result = await adapter.generateContent(prompt);
          return result;
        } catch (err) {
          lastError = err;
          if (isRetryableError(err) && chain.indexOf(adapter) < chain.length - 1) {
            console.warn(`[AI Provider] ${adapter._label} unavailable (${err?.status ?? err?.message}), trying next provider`);
            continue;
          }
          throw err;
        }
      }

      throw lastError;
    },
  };
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Creates the right AI model for the given user tier.
 *
 * @param {"PRO"|"FREE"} tier - User's subscription tier
 * @returns {{ generateContent(prompt: string): Promise<{ response: { text(): string } }> }}
 */
export function createModel(tier = "FREE") {
  const or1 = createOpenRouterAdapter(OPENROUTER_FREE_MODELS[0], "free-primary");
  const or2 = createOpenRouterAdapter(OPENROUTER_FREE_MODELS[1], "free-fallback");

  if (tier === "PRO") {
    // PRO: primary model → fallback to free if primary is down
    const primary = createGeminiAdapter();
    const fallbacks = [or1, or2].filter(Boolean);
    console.log("[AI Provider] Using primary model (PRO tier)");
    return withFallback(primary, fallbacks);
  }

  // FREE: OpenRouter chain → ultimate fallback to Gemini if OR key missing
  if (or1 || or2) {
    const freePrimary = or1 ?? or2;
    const freeFallbacks = or1 && or2 ? [or2] : [];
    console.log("[AI Provider] Using free model chain (FREE tier)");
    return withFallback(freePrimary, freeFallbacks);
  }

  // No OpenRouter key — fall back to Gemini even for free users
  console.warn("[AI Provider] OPENROUTER_API_KEY not set — using primary model for FREE user (fallback)");
  return createGeminiAdapter();
}

/**
 * Returns true if OpenRouter is configured and available as a fallback.
 */
export function isOpenRouterConfigured() {
  return Boolean(process.env.OPENROUTER_API_KEY);
}
