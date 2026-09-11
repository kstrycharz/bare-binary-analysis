import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Standalone output keeps the production image small and, more importantly,
  // makes the air-gap bundle (M6) a single self-contained tree.
  output: "standalone",
  reactStrictMode: true,
  poweredByHeader: false,
  eslint: { ignoreDuringBuilds: false },
  typescript: { ignoreBuildErrors: false },

  // There is deliberately no `rewrites()` here. Rewrites are resolved at BUILD
  // time and baked into the routes manifest, so an image built without
  // BARE_API_URL set proxies to localhost forever — and because
  // server-rendered pages read the env at runtime, the symptom is that every
  // page loads fine and only browser-initiated calls (upload, triage, status
  // changes) fail with a 500. The proxy lives in app/api/[...path]/route.ts,
  // which reads the env per request.
};

export default nextConfig;
