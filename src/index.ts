#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/server";
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import { z } from "zod";
import { createRequire } from "node:module";

import { androidApiExtractor } from "./tools/android/api-extractor.js";
import { apkManifestAnalyzer } from "./tools/android/manifest-analyzer.js";
import { apkPermissionsChecker } from "./tools/android/permissions-checker.js";
import { androidGoogleServices } from "./tools/android/google-services.js";
import { androidSecretsScanner } from "./tools/android/secrets-scanner.js";
import { androidNativeLibraries } from "./tools/android/native-libraries.js";
import { apkDiff } from "./tools/android/apk-diff.js";

// Single source of truth for the version: package.json (always shipped in the npm package).
const { version } = createRequire(import.meta.url)("../package.json") as { version: string };

// MCP SDK v2: tool input schemas are full schema objects (z.object), not raw shapes.
// Each tool module still exports a raw shape in `schema`; it is wrapped here.
function createServer(): McpServer {
  const server = new McpServer({
    name: "mobile-re-mcp",
    version,
  });

  // Android tools
  server.registerTool(
    "android_api_extractor",
    {
      description: androidApiExtractor.description,
      inputSchema: z.object(androidApiExtractor.schema),
    },
    androidApiExtractor.handler
  );

  server.registerTool(
    "apk_manifest_analyzer",
    {
      description: apkManifestAnalyzer.description,
      inputSchema: z.object(apkManifestAnalyzer.schema),
    },
    apkManifestAnalyzer.handler
  );

  server.registerTool(
    "apk_permissions_checker",
    {
      description: apkPermissionsChecker.description,
      inputSchema: z.object(apkPermissionsChecker.schema),
    },
    apkPermissionsChecker.handler
  );

  server.registerTool(
    "android_google_services",
    {
      description: androidGoogleServices.description,
      inputSchema: z.object(androidGoogleServices.schema),
    },
    androidGoogleServices.handler
  );

  server.registerTool(
    "android_secrets_scanner",
    {
      description: androidSecretsScanner.description,
      inputSchema: z.object(androidSecretsScanner.schema),
    },
    androidSecretsScanner.handler
  );

  server.registerTool(
    "android_native_libraries",
    {
      description: androidNativeLibraries.description,
      inputSchema: z.object(androidNativeLibraries.schema),
    },
    androidNativeLibraries.handler
  );

  server.registerTool(
    "apk_diff",
    {
      description: apkDiff.description,
      inputSchema: z.object(apkDiff.schema),
    },
    apkDiff.handler
  );

  return server;
}

// stdout is the JSON-RPC channel: log to stderr only.
const handle = serveStdio(() => createServer());

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    void handle.close().finally(() => process.exit(0));
  });
}
