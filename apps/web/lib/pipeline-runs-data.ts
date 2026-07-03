export type PipelineRunSummary = {
  runId: string;
  asset: string;
  hypothesisCount: number;
  blockedCount: number;
  reportTitle: string | null;
  evidenceCount: number;
};

export const fallbackPipelineRuns: PipelineRunSummary[] = [
  {
    runId: "dry_run_2026_07_03_001",
    asset: "api.example.com",
    hypothesisCount: 3,
    blockedCount: 1,
    reportTitle: "普通用户可访问其他用户私有文件 metadata",
    evidenceCount: 4,
  },
  {
    runId: "dry_run_2026_07_02_002",
    asset: "app.example.com",
    hypothesisCount: 2,
    blockedCount: 2,
    reportTitle: "普通成员可能修改团队邀请设置",
    evidenceCount: 1,
  },
  {
    runId: "dry_run_2026_07_01_004",
    asset: "admin.example.com",
    hypothesisCount: 1,
    blockedCount: 1,
    reportTitle: "管理员导出流程缺少低风险验证证据",
    evidenceCount: 0,
  },
];
