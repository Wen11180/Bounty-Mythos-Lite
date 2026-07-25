import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const webRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

test("control-center display mappings use truthful Chinese labels and deny unsafe permissions", async () => {
  const { dataModeDisplay, safetyStateDisplay } = await import("./control-center-display.ts");

  assert.deepEqual(
    ["live", "dry_run", "demo", "stale", "offline"].map((state) =>
      dataModeDisplay(state),
    ),
    [
      { state: "live", label: "实时数据", tone: "safe" },
      { state: "dry_run", label: "安全演练", tone: "advisory" },
      { state: "demo", label: "演示数据", tone: "neutral" },
      { state: "stale", label: "数据已过期", tone: "approval" },
      { state: "offline", label: "连接离线", tone: "danger" },
    ],
  );

  assert.deepEqual(
    ["blocked", "approval_required", "report_chain_unsafe"].map((state) =>
      safetyStateDisplay({
        state,
        execution_allowed: true,
        report_submission_allowed: true,
      }),
    ),
    [
      {
        state: "blocked",
        label: "已阻止",
        tone: "danger",
        executionAllowed: false,
        reportSubmissionAllowed: false,
      },
      {
        state: "approval_required",
        label: "需要人工批准",
        tone: "approval",
        executionAllowed: false,
        reportSubmissionAllowed: false,
      },
      {
        state: "report_chain_unsafe",
        label: "报告链不安全",
        tone: "danger",
        executionAllowed: false,
        reportSubmissionAllowed: false,
      },
    ],
  );
});

test("repository contains the Radix shadcn contract and Precision Ops shared primitives", async () => {
  const componentsConfig = JSON.parse(
    await readFile(path.join(webRoot, "components.json"), "utf8"),
  ) as {
    style?: string;
    aliases?: { ui?: string };
    tailwind?: { css?: string; cssVariables?: boolean };
  };
  const globals = await readFile(path.join(webRoot, "app", "globals.css"), "utf8");
  const sharedFiles = [
    "app-shell.tsx",
    "command-bar.tsx",
    "data-mode-badge.tsx",
    "safety-state-badge.tsx",
    "metric.tsx",
    "section-header.tsx",
    "panel-state.tsx",
    "responsive-inspector.tsx",
  ];
  const sharedSources = (
    await Promise.all(
      sharedFiles.map((file) =>
        readFile(path.join(webRoot, "components", "control-center", file), "utf8"),
      ),
    )
  ).join("\n");

  assert.match(componentsConfig.style ?? "", /^radix-/);
  assert.equal(componentsConfig.aliases?.ui, "@/components/ui");
  assert.equal(componentsConfig.tailwind?.css, "app/globals.css");
  assert.equal(componentsConfig.tailwind?.cssVariables, true);

  assert.match(globals, /^@import "tailwindcss";/m);
  assert.match(globals, /--surface:\s*#0a0f16;/);
  assert.match(globals, /--surface-glass:\s*rgba\(15, 23, 34, 0\.88\);/);
  assert.match(globals, /--primary:\s*#2388ff;/);
  assert.match(globals, /--safe:\s*#2fd17b;/);
  assert.match(globals, /--approval:\s*#f2b84b;/);
  assert.match(globals, /--danger:\s*#f05d68;/);
  assert.match(globals, /--advisory:\s*#9b7cff;/);
  assert.match(globals, /--radius:\s*0\.375rem;/);
  assert.doesNotMatch(globals, /@tailwind\s+(base|components|utilities)/);

  assert.doesNotMatch(
    sharedSources,
    /\$18,650|73\.4%|app\.example\.com|示例项目|active scan tasks[^\n]*28/i,
  );
});

test("portaled Radix content preserves the Precision Ops token scope", async () => {
  const portalFiles = [
    "dialog.tsx",
    "sheet.tsx",
    "select.tsx",
    "dropdown-menu.tsx",
    "tooltip.tsx",
  ];

  for (const file of portalFiles) {
    const source = await readFile(path.join(webRoot, "components", "ui", file), "utf8");
    assert.match(source, /precision-ops/, `${file} must scope portaled content tokens`);
  }
});

test("responsive inspector uses one child instance and cleans up matchMedia", async () => {
  const inspector = await readFile(
    path.join(webRoot, "components", "control-center", "responsive-inspector.tsx"),
    "utf8",
  );
  assert.match(inspector, /window\.matchMedia\(/);
  assert.match(inspector, /addEventListener\("change"/);
  assert.match(inspector, /removeEventListener\("change"/);
  assert.equal((inspector.match(/\{children\}/g) ?? []).length, 1);
});

test("application shell provides an accessible mobile main navigation", async () => {
  const appShell = await readFile(
    path.join(webRoot, "components", "control-center", "app-shell.tsx"),
    "utf8",
  );
  assert.match(appShell, /<Sheet/);
  assert.match(appShell, /<SheetTrigger/);
  assert.match(appShell, /<Menu/);
  assert.match(appShell, /aria-label="打开主导航"/);
  assert.match(appShell, /md:hidden/);
});

test("loading panel announces status and respects reduced motion", async () => {
  const panelState = await readFile(
    path.join(webRoot, "components", "control-center", "panel-state.tsx"),
    "utf8",
  );
  assert.match(panelState, /role="status"/);
  assert.match(panelState, /aria-live="polite"/);
  assert.match(panelState, /aria-busy="true"/);
  assert.match(panelState, /motion-reduce:animate-none/);
});
