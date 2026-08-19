import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

const chromeBin = process.env.CHROME_BIN || "chromium";
const dashboardUrl = process.env.DASHBOARD_URL || "http://localhost:5173/";
const remotePort = Number(process.env.CHROME_REMOTE_PORT || 9337);
const dashboardAdminUsername = process.env.DASHBOARD_ADMIN_USERNAME || "";
const dashboardAdminPassword = process.env.DASHBOARD_ADMIN_PASSWORD || "";
const dashboardExpectedRole = (
  process.env.DASHBOARD_EXPECT_ROLE || "ADMIN"
).toUpperCase();
const expectNoEvaluationData =
  process.env.DASHBOARD_EXPECT_NO_EVALUATION === "true";
const ignoreCertificateErrors =
  process.env.CHROME_IGNORE_CERT_ERRORS === "true";
const suspendTestDid = process.env.SUSPEND_TEST_DID ||
  "did:fabric:6074c200-b69f-4950-b592-fdf9d60330a1";
const statusChangeReason = "Phase 7 dashboard smoke test";

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchJson(url, attempts = 50) {
  let lastError;

  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      const response = await fetch(url);

      if (response.ok) {
        return response.json();
      }
    } catch (error) {
      lastError = error;
    }

    await wait(150);
  }

  throw lastError || new Error(`Unable to fetch ${url}`);
}

function connectWebSocket(url) {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(url);

    socket.addEventListener("open", () => resolve(socket), {
      once: true
    });
    socket.addEventListener("error", () => {
      reject(new Error("Unable to connect to Chrome DevTools"));
    }, {
      once: true
    });
  });
}

function createChromeClient(socket) {
  let nextId = 1;
  const pending = new Map();
  const consoleMessages = [];
  const exceptions = [];
  const networkFailures = [];

  socket.addEventListener("message", (event) => {
    const message = JSON.parse(event.data);

    if (message.id && pending.has(message.id)) {
      const {
        resolve,
        reject
      } = pending.get(message.id);

      pending.delete(message.id);

      if (message.error) {
        reject(new Error(message.error.message));
      } else {
        resolve(message.result);
      }

      return;
    }

    if (message.method === "Runtime.consoleAPICalled") {
      consoleMessages.push({
        type: message.params.type,
        text: message.params.args
          .map((arg) => arg.value || arg.description || "")
          .join(" ")
      });
    }

    if (message.method === "Runtime.exceptionThrown") {
      const exception = message.params.exceptionDetails.exception;

      exceptions.push(
        exception?.description ||
        exception?.value ||
        message.params.exceptionDetails.text
      );
    }

    if (message.method === "Network.loadingFailed") {
      networkFailures.push({
        requestId: message.params.requestId,
        errorText: message.params.errorText
      });
    }
  });

  function send(method, params = {}) {
    const id = nextId;

    nextId += 1;
    socket.send(JSON.stringify({
      id,
      method,
      params
    }));

    return new Promise((resolve, reject) => {
      pending.set(id, {
        resolve,
        reject
      });
    });
  }

  async function evaluate(expression) {
    const result = await send("Runtime.evaluate", {
      expression,
      awaitPromise: true,
      returnByValue: true
    });

    if (result.exceptionDetails) {
      const exception = result.exceptionDetails.exception;
      const message = exception?.description ||
        exception?.value ||
        result.exceptionDetails.text;

      throw new Error(message);
    }

    return result.result.value;
  }

  return {
    send,
    evaluate,
    consoleMessages,
    exceptions,
    networkFailures
  };
}

async function waitForCondition(client, expression, label, timeoutMs = 10000) {
  const startedAt = Date.now();

  while (Date.now() - startedAt < timeoutMs) {
    if (await client.evaluate(`Boolean(${expression})`)) {
      return;
    }

    await wait(150);
  }

  const pageState = await client.evaluate(`
    (() => ({
      url: document.URL,
      readyState: document.readyState,
      text: document.body.innerText.slice(0, 500)
    }))()
  `);

  throw new Error(
    `Timed out waiting for ${label}: ${JSON.stringify(pageState)}`
  );
}

async function clickButton(client, text) {
  const clicked = await client.evaluate(`
    (() => {
      const button = [...document.querySelectorAll("button")]
        .find((candidate) => candidate.textContent.includes(${JSON.stringify(text)}));

      if (!button) return false;
      button.click();
      return true;
    })()
  `);

  if (!clicked) {
    throw new Error(`Button not found: ${text}`);
  }
}

async function clickCloseDetails(client) {
  await client.evaluate(`
    (() => {
      const button = document.querySelector("button[title='Close details']");

      if (button) button.click();
    })()
  `);
}

async function setSearch(client, placeholderText, value) {
  const updated = await client.evaluate(`
    (() => {
      const input = [...document.querySelectorAll("input[type='search']")]
        .find((candidate) => candidate.placeholder.includes(${JSON.stringify(placeholderText)}));

      if (!input) return false;
      const setter = Object.getOwnPropertyDescriptor(
        HTMLInputElement.prototype,
        "value"
      ).set;
      setter.call(input, ${JSON.stringify(value)});
      input.dispatchEvent(new Event("input", { bubbles: true }));
      return true;
    })()
  `);

  if (!updated) {
    throw new Error(`Search field not found: ${placeholderText}`);
  }
}

async function setInputByName(client, name, value) {
  const updated = await client.evaluate(`
    (() => {
      const input = document.querySelector(
        ${JSON.stringify(`input[name="${name}"]`)}
      );

      if (!input) return false;
      const setter = Object.getOwnPropertyDescriptor(
        HTMLInputElement.prototype,
        "value"
      ).set;
      setter.call(input, ${JSON.stringify(value)});
      input.dispatchEvent(new Event("input", { bubbles: true }));
      return true;
    })()
  `);

  if (!updated) {
    throw new Error(`Input not found: ${name}`);
  }
}

async function setSelectByIndex(client, index, value) {
  const updated = await client.evaluate(`
    (() => {
      const select = document.querySelectorAll("select")[${index}];

      if (!select) return false;
      select.value = ${JSON.stringify(value)};
      select.dispatchEvent(new Event("change", { bubbles: true }));
      return true;
    })()
  `);

  if (!updated) {
    throw new Error(`Select not found at index ${index}`);
  }
}

async function fillReason(client, reason) {
  const updated = await client.evaluate(`
    (() => {
      const textarea = document.querySelector("textarea");

      if (!textarea) return false;
      const setter = Object.getOwnPropertyDescriptor(
        HTMLTextAreaElement.prototype,
        "value"
      ).set;
      setter.call(textarea, ${JSON.stringify(reason)});
      textarea.dispatchEvent(new Event("input", { bubbles: true }));
      return true;
    })()
  `);

  if (!updated) {
    throw new Error("Reason field not found");
  }
}

async function loginIfNeeded(client) {
  const needsLogin = await client.evaluate(
    `Boolean(document.querySelector("input[name='username']"))`
  );

  if (!needsLogin) {
    return;
  }

  if (!dashboardAdminUsername || !dashboardAdminPassword) {
    throw new Error(
      "Dashboard login requires DASHBOARD_ADMIN_USERNAME and DASHBOARD_ADMIN_PASSWORD"
    );
  }

  await setInputByName(client, "username", dashboardAdminUsername);
  await setInputByName(client, "password", dashboardAdminPassword);
  await clickButton(client, "Sign in");
  await waitForCondition(
    client,
    `document.body.innerText.includes("Total Devices")`,
    "authenticated overview statistics"
  );
}

async function runChecks(client) {
  await client.send("Runtime.enable");
  await client.send("Page.enable");
  await client.send("Network.enable");
  await client.send("Page.navigate", {
    url: dashboardUrl
  });

  await waitForCondition(
    client,
    `document.body.innerText.includes("Total Devices") ||
      document.querySelector("input[name='username']")`,
    "dashboard or login view"
  );
  await loginIfNeeded(client);
  await waitForCondition(
    client,
    `document.body.innerText.includes("Total Devices")`,
    "overview statistics"
  );

  const overview = await client.evaluate(`
    (() => ({
      adminRoleShown: document.body.innerText.includes(${JSON.stringify(dashboardExpectedRole)}),
      hasHealth: document.body.innerText.includes("Fabric") &&
        document.body.innerText.includes("connected"),
      totalDevicesText: [...document.querySelectorAll(".stat-card")]
        .find((card) => card.textContent.includes("Total Devices"))
        ?.textContent || "",
      hasAuditSummary: document.body.innerText.includes("Authentication Events")
    }))()
  `);

  await clickButton(client, "Devices");
  await waitForCondition(
    client,
    `document.body.innerText.includes("Registered Devices") &&
      document.querySelectorAll("tbody tr").length > 0`,
    "devices table"
  );

  const deviceRows = await client.evaluate(
    `document.querySelectorAll("tbody tr").length`
  );

  const detailsOpened = await client.evaluate(`
    (() => {
      const button = document.querySelector("button[title='View device details']");

      if (!button) return false;
      button.click();
      return true;
    })()
  `);

  if (!detailsOpened) {
    throw new Error("Device details button not found");
  }

  await waitForCondition(
    client,
    `document.body.innerText.includes("Device Details") &&
      document.body.innerText.includes("Public Key")`,
    "device details"
  );
  await clickCloseDetails(client);

  if (dashboardExpectedRole === "ADMIN") {
    await clickButton(client, "Devices");
    await setSearch(client, "DID", suspendTestDid);
    await waitForCondition(
      client,
      `document.body.innerText.includes("Phase 3 Suspend Test Device")`,
      "suspend-test device row"
    );

    await clickButton(client, "Suspend");
    await waitForCondition(
      client,
      `document.body.innerText.includes("Suspend Device") &&
        document.querySelector("textarea")`,
      "suspend dialog"
    );
    await fillReason(client, statusChangeReason);
    await clickButton(client, "Suspend Device");
    await waitForCondition(
      client,
      `document.body.innerText.includes("SUSPENDED") &&
        document.body.innerText.includes("Activate")`,
      "suspended status"
    );

    await clickButton(client, "Activate");
    await waitForCondition(
      client,
      `document.body.innerText.includes("Activate Device")`,
      "activate dialog"
    );
    await clickButton(client, "Activate Device");
    await waitForCondition(
      client,
      `document.body.innerText.includes("ACTIVE") &&
        document.body.innerText.includes("Suspend")`,
      "active status restoration"
    );
  } else {
    const privilegedButtons = await client.evaluate(`
      [...document.querySelectorAll("button")]
        .map((button) => button.textContent.trim())
        .filter((text) =>
          text === "Suspend" ||
          text === "Activate" ||
          text === "Revoke"
        )
    `);

    if (privilegedButtons.length > 0) {
      throw new Error(
        `Viewer role can see privileged buttons: ${privilegedButtons.join(", ")}`
      );
    }
  }

  await clickButton(client, "Authentication Audit");
  await waitForCondition(
    client,
    `document.body.innerText.includes("Authentication Audit") &&
      document.querySelectorAll("tbody tr").length > 0`,
    "audit table"
  );
  await setSelectByIndex(client, 0, "DENIED");
  await waitForCondition(
    client,
    `document.body.innerText.includes("DENIED")`,
    "decision filter"
  );
  await setSelectByIndex(client, 1, "MAC_MISMATCH");
  await waitForCondition(
    client,
    `document.body.innerText.includes("MAC_MISMATCH")`,
    "spoofing filter"
  );

  await clickButton(client, "Spoofing Alerts");
  await waitForCondition(
    client,
    `document.body.innerText.includes("Spoofing Alerts")`,
    "spoofing alerts view"
  );

  const alerts = await client.evaluate(`
    (() => {
      const classifications = [...new Set(
        [...document.querySelectorAll("[class*='spoofing-']")]
          .map((item) => item.textContent.trim())
      )];

      return {
        alertRows: document.querySelectorAll("tbody tr").length,
        classifications
      };
    })()
  `);

  await clickButton(client, "Performance");
  await waitForCondition(
    client,
    `document.body.innerText.includes("Live Operational Metrics") &&
      document.body.innerText.includes("Formal Evaluation Metrics")`,
    "performance view"
  );

  const performance = await client.evaluate(`
    (() => ({
      hasLiveMetrics: document.body.innerText.includes("Attempts Since Start"),
      hasNoEvaluationMessage:
        document.body.innerText.includes("No evaluation data available"),
      hasConcurrencyTable:
        document.querySelectorAll("table.performance-table tbody tr").length > 0
    }))()
  `);

  if (expectNoEvaluationData && !performance.hasNoEvaluationMessage) {
    throw new Error("Performance view did not show the no-evaluation-data state");
  }

  if (expectNoEvaluationData && performance.hasConcurrencyTable) {
    throw new Error("Performance view showed formal concurrency rows without evaluation data");
  }

  return {
    overview,
    deviceRows,
    alerts,
    performance
  };
}

async function main() {
  const configuredUserDataDir = process.env.CHROME_USER_DATA_DIR || "";
  const userDataDir = configuredUserDataDir ||
    await mkdtemp(path.join(tmpdir(), "dashboard-smoke-"));
  const chromeArgs = [
    "--headless=new",
    "--disable-gpu",
    "--no-sandbox",
    `--user-data-dir=${userDataDir}`,
    `--remote-debugging-port=${remotePort}`,
    dashboardUrl
  ];

  if (ignoreCertificateErrors) {
    chromeArgs.splice(3, 0, "--ignore-certificate-errors");
  }

  const chrome = spawn(chromeBin, chromeArgs, {
    stdio: ["ignore", "ignore", "pipe"]
  });
  let chromeErrors = "";

  chrome.stderr.on("data", (chunk) => {
    chromeErrors += chunk.toString();
  });

  try {
    const targets = await fetchJson(`http://127.0.0.1:${remotePort}/json`);
    const page = targets.find((target) => target.type === "page");

    if (!page?.webSocketDebuggerUrl) {
      throw new Error("Unable to locate dashboard page in Chrome");
    }

    const socket = await connectWebSocket(page.webSocketDebuggerUrl);
    const client = createChromeClient(socket);
    let checks;

    try {
      checks = await runChecks(client);
    } catch (error) {
      console.error(JSON.stringify({
        consoleMessages: client.consoleMessages,
        browserExceptions: client.exceptions,
        networkFailures: client.networkFailures
      }, null, 2));
      throw error;
    }
    const seriousConsoleMessages = client.consoleMessages.filter((message) =>
      ["error", "assert"].includes(message.type)
    );

    socket.close();

    console.log(JSON.stringify({
      dashboardUrl,
      checks,
      browserExceptions: client.exceptions,
      seriousConsoleMessages
    }, null, 2));

    if (client.exceptions.length > 0 || seriousConsoleMessages.length > 0) {
      process.exitCode = 1;
    }
  } finally {
    chrome.kill("SIGTERM");

    if (!configuredUserDataDir) {
      try {
        await rm(userDataDir, {
          recursive: true,
          force: true
        });
      } catch {
        // Chrome can keep transient profile handles alive briefly.
      }
    }
  }

  if (chromeErrors.includes("CONSOLE")) {
    console.error(chromeErrors);
  }
}

main().catch((error) => {
  console.error(`Dashboard smoke test failed: ${error.message}`);
  process.exit(1);
});
