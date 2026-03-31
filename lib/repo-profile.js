const PROFILE_HINTS = [
  {
    id: "nextjs_app",
    label: "Next.js",
    test(file) {
      return /^app\//.test(file.filename) || /^pages\//.test(file.filename) || /next\.config/.test(file.filename);
    },
  },
  {
    id: "react_ui",
    label: "React",
    test(file) {
      return /\.(jsx|tsx)$/.test(file.filename) || /react/i.test(file.patch || "");
    },
  },
  {
    id: "node_backend",
    label: "Node backend",
    test(file) {
      return /\.(js|ts)$/.test(file.filename) && /(express|fastify|koa|hono|router)/i.test(file.patch || "");
    },
  },
  {
    id: "auth_surface",
    label: "Authentication",
    test(file) {
      return /auth|login|session|token|permission|acl|rbac/i.test(file.filename);
    },
  },
  {
    id: "payments_surface",
    label: "Payments",
    test(file) {
      return /billing|payment|checkout|invoice|subscription|stripe/i.test(file.filename);
    },
  },
  {
    id: "data_access_surface",
    label: "Data access",
    test(file) {
      return /db|database|sql|migration|schema|supabase|prisma|typeorm/i.test(file.filename);
    },
  },
];

function detectCriticalAreas(files) {
  const criticalAreas = new Set();

  for (const file of files) {
    if (/auth|login|session|permission|rbac|acl|token/i.test(file.filename)) {
      criticalAreas.add("auth");
    }
    if (/billing|payment|checkout|invoice|subscription|stripe/i.test(file.filename)) {
      criticalAreas.add("payments");
    }
    if (/db|database|schema|migration|sql|supabase|prisma/i.test(file.filename)) {
      criticalAreas.add("data");
    }
    if (/api|route|controller|handler|webhook/i.test(file.filename)) {
      criticalAreas.add("api");
    }
  }

  return Array.from(criticalAreas);
}

export function buildRepoProfile({ repoFullName, files }) {
  const capabilities = new Set();

  for (const file of files) {
    for (const hint of PROFILE_HINTS) {
      if (hint.test(file)) {
        capabilities.add(hint.id);
      }
    }
  }

  const criticalAreas = detectCriticalAreas(files);
  const riskLevel = criticalAreas.length >= 2 ? "high" : criticalAreas.length === 1 ? "medium" : "normal";

  return {
    repoFullName,
    capabilities: Array.from(capabilities),
    criticalAreas,
    riskLevel,
  };
}

export function summarizeRepoProfile(profile) {
  if (!profile) {
    return "Repo profile: generic_codebase. Critical areas: none_detected. Risk level: normal.";
  }

  const capabilities = profile.capabilities.length > 0 ? profile.capabilities.join(", ") : "generic_codebase";
  const criticalAreas = profile.criticalAreas.length > 0 ? profile.criticalAreas.join(", ") : "none_detected";

  return `Repo profile: ${capabilities}. Critical areas: ${criticalAreas}. Risk level: ${profile.riskLevel}.`;
}
