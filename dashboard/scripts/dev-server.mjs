import { createServer as createHttpServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { readFile, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import esbuild from "esbuild";

import {
  buildOptions,
  writeIndexHtml
} from "./build.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(__dirname, "..");
const distDir = path.join(projectRoot, "dist");
const port = Number(process.env.DASHBOARD_PORT || 5173);
const host = process.env.DASHBOARD_HOST || "0.0.0.0";
const watchEnabled = !process.argv.includes("--no-watch");
const httpsEnabled = process.env.DASHBOARD_HTTPS_ENABLED === "true";
const tlsCertPath = process.env.DASHBOARD_TLS_CERT_PATH
  ? path.resolve(projectRoot, process.env.DASHBOARD_TLS_CERT_PATH)
  : "";
const tlsKeyPath = process.env.DASHBOARD_TLS_KEY_PATH
  ? path.resolve(projectRoot, process.env.DASHBOARD_TLS_KEY_PATH)
  : "";

const contentTypes = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".map": "application/json; charset=utf-8",
  ".svg": "image/svg+xml"
};

function resolveRequestPath(url) {
  const parsed = new URL(url, `http://${host}:${port}`);
  const pathname = decodeURIComponent(parsed.pathname);
  const relativePath = pathname === "/" ? "index.html" : pathname.slice(1);
  const resolvedPath = path.resolve(distDir, relativePath);

  if (!resolvedPath.startsWith(distDir)) {
    return path.join(distDir, "index.html");
  }

  return resolvedPath;
}

async function readResponseFile(requestPath) {
  try {
    const fileStat = await stat(requestPath);

    if (fileStat.isFile()) {
      return requestPath;
    }
  } catch {
    return path.join(distDir, "index.html");
  }

  return path.join(distDir, "index.html");
}

async function startServer() {
  process.env.NODE_ENV = process.env.NODE_ENV || "development";
  await writeIndexHtml();

  if (watchEnabled) {
    const context = await esbuild.context({
      ...buildOptions,
      minify: false,
      sourcemap: true
    });

    await context.watch();
  } else {
    await esbuild.build(buildOptions);
  }

  const requestHandler = async (request, response) => {
    const requestPath = resolveRequestPath(request.url || "/");
    const filePath = await readResponseFile(requestPath);
    const extension = path.extname(filePath);

    try {
      const file = await readFile(filePath);

      response.writeHead(200, {
        "Content-Type":
          contentTypes[extension] || "application/octet-stream"
      });
      response.end(file);
    } catch {
      response.writeHead(404, {
        "Content-Type": "text/plain; charset=utf-8"
      });
      response.end("Not found");
    }
  };
  const server = httpsEnabled
    ? createHttpsServer({
      cert: await readFile(tlsCertPath),
      key: await readFile(tlsKeyPath)
    }, requestHandler)
    : createHttpServer(requestHandler);

  server.listen(port, host, () => {
    const protocol = httpsEnabled ? "https" : "http";

    console.log(`Dashboard running at ${protocol}://localhost:${port}`);
  });
}

startServer().catch((error) => {
  console.error(error);
  process.exit(1);
});
