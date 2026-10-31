import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { Cli } from "incur";
import pino from "pino";
import { expect, it, vi } from "vitest";

import { runDirectAnalysis } from "../../../src/application/DirectAnalysis.js";
import { registerCoreNativeCommands } from "../../../src/cli/coreNativeCommands.js";
import { projectCliAnalysisResult } from "../../../src/cli/projectCliAnalysisResult.js";
import type { CliInstance } from "../../../src/cli/types.js";
import { createEvidence, parseEvidence } from "../../../src/domain/evidence.js";
import {
  createEvidenceBundle,
  parseEvidenceBundle,
  type EvidenceBundle,
} from "../../../src/domain/evidenceBundle.js";
import { REA_WORKFLOW_PROVIDER } from "../../../src/domain/investigationProviders.js";
import { ok } from "../../../src/domain/result.js";
import { composedWorkflowFixture } from "../../fixtures/composedWorkflowEvidence.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

const sourceProvider = { id: "fixture", name: "Fixture", version: "1" };
const sourceTarget = {
  path: "/fixtures/native.exe",
  format: "pe" as const,
  sha256: "a".repeat(64),
};

const verifyDirectAnalysisEvidenceBundleCallback = async (
  snapshotPath: string,
) => {
  const fixture = await composedWorkflowFixture();
  let captured: EvidenceBundle | undefined;
  const direct = parseEvidence(
    await runDirectAnalysis(
      fixture.dependencies,
      fixture.path,
      "binary_overview",
      {},
      { snapshotPath, onEvidenceBundle: (bundle) => (captured = bundle) },
    ).then(projectCliAnalysisResult),
  );
  expect(captured?.records.map(({ evidence_id }) => evidence_id)).toContain(
    direct.evidence_id,
  );

  let replayedBundle: EvidenceBundle | undefined;
  const replayed = parseEvidence(
    await runDirectAnalysis(
      fixture.dependencies,
      fixture.path,
      "binary_overview",
      {},
      {
        snapshotPath,
        onEvidenceBundle: (bundle) => (replayedBundle = bundle),
      },
    ).then(projectCliAnalysisResult),
  );
  expect(replayed).toEqual(direct);
  expect(
    replayedBundle?.records.map(({ evidence_id }) => evidence_id),
  ).toContain(replayed.evidence_id);
};

it("exports only the transitive source Evidence closure for a native value trace", async () => {
  const leaf = createEvidence(sourceTarget, sourceProvider, {
    operation: "read_native_source",
    parameters: { address: "0x1000" },
    result: { text: "return 0;" },
  });
  const procedure = createEvidence(sourceTarget, sourceProvider, {
    operation: "analyze_function",
    parameters: { procedure: "main" },
    result: { procedure: { address: "0x1000" } },
    evidenceLinks: [leaf.evidence_id],
  });
  const trace = createEvidence(sourceTarget, REA_WORKFLOW_PROVIDER, {
    operation: "trace_native_values",
    parameters: { procedure: "main" },
    result: { procedures: [{ evidence_id: procedure.evidence_id }] },
    confidence: "derived",
    evidenceLinks: [procedure.evidence_id],
  });
  const unrelated = createEvidence(sourceTarget, sourceProvider, {
    operation: "address_name",
    parameters: { address: "0x2000" },
    result: { name: "unrelated" },
  });
  const sessionBundle = createEvidenceBundle([
    trace,
    procedure,
    leaf,
    unrelated,
  ]);
  const mockRunDirectAnalysis = vi.fn<
    Parameters<typeof registerCoreNativeCommands>[2]
  >(async (_path, _tool, _arguments, options) => {
    options?.onEvidenceBundle?.(sessionBundle);
    return ok(trace);
  });
  const cli = Cli.create("rea-trace-evidence-test", {
    version: "1",
    sync: false,
  });
  registerCoreNativeCommands(
    cli as unknown as CliInstance,
    pino({ enabled: false }),
    mockRunDirectAnalysis,
  );
  const directory = await createTestTempDirectory("rea-trace-evidence-");
  const destination = join(directory, "trace-evidence.json");
  let stdout = "";
  await cli.serve(
    [
      "trace-native-values",
      sourceTarget.path,
      "main",
      "--evidence_output",
      destination,
      "--json",
    ],
    {
      env: {},
      stdout: (text) => {
        stdout += text;
      },
      exit: () => undefined,
    },
  );

  const delivered = JSON.parse(stdout) as { evidence_id: string };
  expect(delivered.evidence_id).toBe(trace.evidence_id);
  expect(mockRunDirectAnalysis).toHaveBeenCalledOnce();
  const exported = parseEvidenceBundle(
    JSON.parse(await readFile(destination, "utf8")),
  );
  expect(exported.records.map(({ evidence_id }) => evidence_id).sort()).toEqual(
    [trace.evidence_id, procedure.evidence_id, leaf.evidence_id].sort(),
  );
  expect(
    exported.records.some(
      ({ evidence_id }) => evidence_id === unrelated.evidence_id,
    ),
  ).toBe(false);

  let summaryOutput = "";
  await cli.serve(
    [
      "trace-native-values",
      "/missing-target",
      "main",
      "--detail",
      "summary",
      "--json",
    ],
    {
      env: {},
      stdout: (text) => {
        summaryOutput += text;
      },
      exit: () => undefined,
    },
  );
  expect(mockRunDirectAnalysis).toHaveBeenCalledOnce();
  expect(summaryOutput).toContain("evidence_output");

  mockRunDirectAnalysis.mockImplementationOnce(
    async (_path, _tool, _arguments, options) => {
      options?.onEvidenceBundle?.(createEvidenceBundle([trace, procedure]));
      return ok(trace);
    },
  );
  const missingSourceDestination = join(directory, "missing-source.json");
  let missingSourceOutput = "";
  await cli.serve(
    [
      "trace-native-values",
      sourceTarget.path,
      "main",
      "--evidence_output",
      missingSourceDestination,
      "--json",
    ],
    {
      env: {},
      stdout: (text) => {
        missingSourceOutput += text;
      },
      exit: () => undefined,
    },
  );
  expect(missingSourceOutput).toContain(
    "did not retain a source Evidence record",
  );
  await expect(readFile(missingSourceDestination, "utf8")).rejects.toThrow();
  expect(mockRunDirectAnalysis).toHaveBeenCalledTimes(2);

  await verifyDirectAnalysisEvidenceBundleCallback(
    join(directory, "analysis-snapshot.json"),
  );
});
