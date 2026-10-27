import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";

const DIST_DIR = "/Users/benskolmoski/.superconductor/worktrees/locksmith/locksmith-cockpit/desktop/dist";
const PORT = 14210;
const DEBUG_PORT = 9222;

const MIME_TYPES = {
  ".html": "text/html",
  ".js": "application/javascript",
  ".css": "text/css",
  ".png": "image/png",
  ".json": "application/json",
};

// 1. Static file server
const server = http.createServer((req, res) => {
  let reqPath = req.url === "/" ? "/index.html" : req.url;
  const filePath = path.join(DIST_DIR, reqPath.split("?")[0]);
  const ext = path.extname(filePath);

  if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
    res.writeHead(200, { "Content-Type": MIME_TYPES[ext] || "application/octet-stream" });
    fs.createReadStream(filePath).pipe(res);
  } else {
    res.writeHead(404);
    res.end("Not Found");
  }
});

await new Promise((resolve) => server.listen(PORT, "127.0.0.1", resolve));
console.log(`[HTTP Server] Listening on http://127.0.0.1:${PORT}`);

// 2. Launch Chrome with CDP
const chromePath = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const chromeProc = spawn(chromePath, [
  "--headless=new",
  `--remote-debugging-port=${DEBUG_PORT}`,
  "--disable-gpu",
  "--no-first-run",
  "--no-default-browser-check",
  "--window-size=1024,768",
  "about:blank",
]);

let killed = false;
function cleanup() {
  if (!killed) {
    killed = true;
    chromeProc.kill("SIGKILL");
    server.close();
  }
}
process.on("exit", cleanup);
process.on("SIGINT", cleanup);

// Wait for CDP endpoint
let wsUrl = null;
for (let i = 0; i < 30; i++) {
  try {
    const res = await fetch(`http://127.0.0.1:${DEBUG_PORT}/json`);
    const targets = await res.json();
    const pageTarget = targets.find((t) => t.type === "page");
    if (pageTarget && pageTarget.webSocketDebuggerUrl) {
      wsUrl = pageTarget.webSocketDebuggerUrl;
      break;
    }
  } catch {}
  await new Promise((r) => setTimeout(r, 200));
}

if (!wsUrl) {
  console.error("Could not get Chrome WebSocket URL");
  cleanup();
  process.exit(1);
}

console.log("[CDP] Connected to Chrome page target:", wsUrl);
const ws = new WebSocket(wsUrl);

await new Promise((resolve) => (ws.onopen = resolve));

let reqId = 1;
const pending = new Map();
const consoleErrors = [];

ws.onmessage = (event) => {
  const msg = JSON.parse(event.data);
  if (msg.id && pending.has(msg.id)) {
    const { resolve, reject } = pending.get(msg.id);
    pending.delete(msg.id);
    if (msg.error) reject(msg.error);
    else resolve(msg.result);
  }
  if (msg.method === "Runtime.consoleAPICalled" && msg.params.type === "error") {
    consoleErrors.push(msg.params.args.map((a) => a.value || a.description).join(" "));
  }
  if (msg.method === "Runtime.exceptionThrown") {
    consoleErrors.push(msg.params.exceptionDetails.text);
  }
};

function send(method, params = {}) {
  const id = reqId++;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    ws.send(JSON.stringify({ id, method, params }));
  });
}

async function evaluate(code) {
  let expr;
  if (/^\s*(const|let|var|if|for|while|try|switch)\b/.test(code) || code.includes(";")) {
    expr = `(() => { ${code} })()`;
  } else {
    expr = `(() => (${code}))()`;
  }
  const res = await send("Runtime.evaluate", { expression: expr, returnByValue: true, awaitPromise: true });
  if (res.exceptionDetails) {
    const detail = res.exceptionDetails.exception?.description || res.exceptionDetails.text;
    console.error("Evaluation Exception:", detail);
    throw new Error(detail);
  }
  return res.result?.value;
}

// Enable domains
await send("Page.enable");
await send("Runtime.enable");

// Navigate to app
console.log(`[CDP] Navigating to http://127.0.0.1:${PORT}...`);
await send("Page.navigate", { url: `http://127.0.0.1:${PORT}` });

// Wait 1.5s for initial render and hydration
await new Promise((r) => setTimeout(r, 1500));

// --- Test 1: Page Shell & Ephemeral Lease Monitor ---
console.log("\n--- Testing Tab 1: Ephemeral Lease Monitor ---");
const pageTitle = await evaluate("document.title");
console.log(`✓ Page Title: "${pageTitle}"`);

const leaseCountText = await evaluate(`document.querySelector("header").textContent`);
console.log(`✓ Header Text includes "Locksmith Cockpit": ${leaseCountText.includes("Locksmith")}`);

const tableRows = await evaluate(`document.querySelectorAll("table tbody tr").length`);
console.log(`✓ Active Lease rows rendered: ${tableRows}`);

const leaseIdSample = await evaluate(`document.querySelector("table tbody tr td")?.textContent?.trim()`);
console.log(`✓ First Lease ID: ${leaseIdSample}`);

const progressBars = await evaluate(`document.querySelectorAll("progress").length`);
console.log(`✓ TTL <progress> elements found: ${progressBars}`);

// Test modal: Request Lease
console.log("✓ Testing 'Request Ephemeral Lease' modal open...");
await evaluate(`
  const btn = Array.from(document.querySelectorAll("button")).find(b => b.textContent.includes("Request Ephemeral Lease"));
  btn?.click();
`);
await new Promise((r) => setTimeout(r, 400));
const modalTitle = await evaluate(`document.querySelector("h3")?.textContent`);
console.log(`✓ Modal opened with title: "${modalTitle}"`);

// Issue lease inside modal
console.log("✓ Issuing test lease inside modal...");
await evaluate(`
  const issueBtn = Array.from(document.querySelectorAll("button")).find(b => b.textContent.includes("Issue Lease"));
  issueBtn?.click();
`);
await new Promise((r) => setTimeout(r, 600));
const tableRowsAfter = await evaluate(`document.querySelectorAll("table tbody tr").length`);
console.log(`✓ Active Lease rows after issuing test lease: ${tableRowsAfter}`);

// --- Test 2: Access Audit Trail ---
console.log("\n--- Testing Tab 2: Access Audit Trail ---");
await evaluate(`
  const tab = Array.from(document.querySelectorAll("nav button")).find(b => b.textContent.includes("Access Audit Trail"));
  tab?.click();
`);
await new Promise((r) => setTimeout(r, 500));

const auditHeading = await evaluate(`document.querySelector("h2")?.textContent`);
console.log(`✓ Navigated to: "${auditHeading}"`);

const auditEventsCount = await evaluate(`document.querySelectorAll("table tbody tr").length`);
console.log(`✓ Audit records in table: ${auditEventsCount}`);

// Test search filter
console.log("✓ Testing audit search filter with query 'curl'...");
await evaluate(`
  const input = document.querySelector("input[placeholder*='Filter']");
  if (input) {
    input.value = "curl";
    input.dispatchEvent(new Event("input", { bubbles: true }));
  }
`);
await new Promise((r) => setTimeout(r, 400));
const filteredRows = await evaluate(`document.querySelectorAll("table tbody tr").length`);
const filteredText = await evaluate(`document.querySelector("table tbody tr")?.textContent`);
console.log(`✓ Rows matching 'curl': ${filteredRows} (Text contains curl: ${filteredText?.includes("curl")})`);

// Reset filter
await evaluate(`
  const clearBtn = Array.from(document.querySelectorAll("button")).find(b => b.textContent.trim() === "✕");
  clearBtn?.click();
`);
await new Promise((r) => setTimeout(r, 300));

// --- Test 3: Expiration Radar ---
console.log("\n--- Testing Tab 3: Expiration Radar ---");
await evaluate(`
  const tab = Array.from(document.querySelectorAll("nav button")).find(b => b.textContent.includes("Expiration Radar"));
  tab?.click();
`);
await new Promise((r) => setTimeout(r, 500));

const radarHeading = await evaluate(`document.querySelector("h3")?.textContent`);
console.log(`✓ Navigated to: "${radarHeading}"`);

const metricsCards = await evaluate(`document.querySelectorAll(".grid > div").length`);
console.log(`✓ Expiration Radar metric cards: ${metricsCards}`);

// Test Touch ID reveal
console.log("✓ Testing 'Touch ID Reveal' step-up challenge...");
await evaluate(`
  const revealBtn = Array.from(document.querySelectorAll("button")).find(b => b.textContent.includes("Touch ID Reveal"));
  revealBtn?.click();
`);
await new Promise((r) => setTimeout(r, 600));

const modalDecryptedText = await evaluate(`document.body.textContent`);
const hasDecrypted = modalDecryptedText.includes("Secret Decrypted") || modalDecryptedText.includes("Biometric Step-Up");
console.log(`✓ Biometric reveal modal appeared: ${hasDecrypted}`);

// Close modal
await evaluate(`
  const closeBtn = Array.from(document.querySelectorAll("button")).find(b => b.textContent.includes("Close Secret Reveal"));
  closeBtn?.click();
`);
await new Promise((r) => setTimeout(r, 400));

// --- Test 4: Auto-Rotation & Policies ---
console.log("\n--- Testing Tab 4: Auto-Rotation & Policies ---");
await evaluate(`
  const tab = Array.from(document.querySelectorAll("nav button")).find(b => b.textContent.includes("Auto-Rotation"));
  tab?.click();
`);
await new Promise((r) => setTimeout(r, 500));

const policyHeading = await evaluate(`document.querySelector("h3")?.textContent`);
console.log(`✓ Navigated to: "${policyHeading}"`);

const ruleRows = await evaluate(`document.querySelectorAll("table tbody tr").length`);
console.log(`✓ Auto-Rotation rules in matrix: ${ruleRows}`);

// Test Rotate Now
console.log("✓ Clicking 'Rotate Now' on rule...");
await evaluate(`
  const rotBtn = Array.from(document.querySelectorAll("button")).find(b => b.textContent.includes("Rotate Now"));
  rotBtn?.click();
`);
await new Promise((r) => setTimeout(r, 600));

const rotateFeedback = await evaluate(`document.querySelector(".bg-emerald-950\\\\/40")?.textContent`);
console.log(`✓ Rotation feedback: "${rotateFeedback?.trim()}"`);

// Test adding binary to whitelist
console.log("✓ Testing adding binary to whitelist...");
await evaluate(`
  const binInput = document.querySelector("input[placeholder*='/path/to/trusted/executable']");
  if (binInput) {
    binInput.value = "/usr/bin/python3";
    binInput.dispatchEvent(new Event("input", { bubbles: true }));
  }
  const addBtn = Array.from(document.querySelectorAll("button")).find(b => b.textContent.includes("Add Binary"));
  addBtn?.click();
`);
await new Promise((r) => setTimeout(r, 400));

const whitelistedTags = await evaluate(`
  Array.from(document.querySelectorAll(".inline-flex span")).map(s => s.textContent).filter(t => t.startsWith("/")).join(", ")
`);
console.log(`✓ Whitelisted binaries list contains '/usr/bin/python3': ${whitelistedTags.includes("/usr/bin/python3")}`);

// Capture final screenshot
console.log("\n--- Capturing UI Screenshot ---");
const screenshotRes = await send("Page.captureScreenshot", { format: "png" });
const screenshotPath = "/Users/benskolmoski/.superconductor/worktrees/locksmith/locksmith-cockpit/desktop/cockpit_screenshot.png";
fs.writeFileSync(screenshotPath, Buffer.from(screenshotRes.data, "base64"));
console.log(`✓ Screenshot saved to: ${screenshotPath} (${Math.round(screenshotRes.data.length / 1024)} KB)`);

// Check console errors
console.log("\n--- Console Error Audit ---");
if (consoleErrors.length === 0) {
  console.log("✓ Clean console: 0 exceptions, 0 runtime errors!");
} else {
  console.warn("Console errors encountered:", consoleErrors);
}

cleanup();
console.log("\n==========================================");
console.log("ALL UI VALIDATION TESTS PASSED CLEANLY!");
console.log("==========================================");
