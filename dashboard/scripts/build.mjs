import { cp, mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import esbuild from "esbuild";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(__dirname, "..");
const distDir = path.join(projectRoot, "dist");
const assetsDir = path.join(distDir, "assets");
const publicDir = path.join(projectRoot, "public");
const apiBaseUrl = process.env.VITE_API_BASE_URL || "";
const isDevelopment = process.env.NODE_ENV === "development";

export const buildOptions = {
  entryPoints: [path.join(projectRoot, "src", "main.jsx")],
  bundle: true,
  outdir: assetsDir,
  entryNames: "main",
  assetNames: "[name]",
  format: "esm",
  sourcemap: true,
  minify: !isDevelopment,
  loader: {
    ".js": "jsx",
    ".jsx": "jsx"
  },
  jsx: "automatic",
  jsxImportSource: "react",
  define: {
    "import.meta.env.VITE_API_BASE_URL": JSON.stringify(apiBaseUrl),
    "process.env.NODE_ENV": JSON.stringify(
      isDevelopment ? "development" : "production"
    )
  }
};

async function copyPublicAssets() {
  try {
    await cp(publicDir, distDir, {
      recursive: true
    });
  } catch (error) {
    if (error.code !== "ENOENT") {
      throw error;
    }
  }
}

export async function writeIndexHtml() {
  await mkdir(distDir, {
    recursive: true
  });
  await copyPublicAssets();
  await writeFile(
    path.join(distDir, "index.html"),
    `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
    <title>Blockchain Authentication | Admin Console</title>
    <link rel="stylesheet" href="/assets/main.css" />
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/assets/main.js"></script>
  </body>
</html>
`,
    "utf8"
  );
}

export async function buildDashboard() {
  await writeIndexHtml();
  await esbuild.build(buildOptions);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  buildDashboard().catch((error) => {
    console.error(error);
    process.exit(1);
  });
}
