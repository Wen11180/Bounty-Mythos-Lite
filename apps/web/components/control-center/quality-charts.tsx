"use client";

import dynamic from "next/dynamic";

import { Metric } from "@/components/control-center/metric";
import { PanelState } from "@/components/control-center/panel-state";
import { SectionHeader } from "@/components/control-center/section-header";
import { buildQualityChartModel, type ControlCenterQuality } from "@/lib/control-center-data";

const EChartsCanvas = dynamic(() => import("./echarts-canvas"), {
  ssr: false,
  loading: () => <PanelState state="loading" className="h-60" title="正在加载研究质量图表" />,
});

interface QualityChartsProps {
  quality: ControlCenterQuality;
}

function formatDuration(seconds: number | null): string | undefined {
  if (seconds === null) {
    return undefined;
  }
  if (seconds < 60) {
    return `${Math.round(seconds)} 秒`;
  }
  if (seconds < 3600) {
    return `${Math.round(seconds / 60)} 分钟`;
  }
  return `${(seconds / 3600).toFixed(1)} 小时`;
}

export function QualityCharts({ quality }: QualityChartsProps) {
  const model = buildQualityChartModel(quality);

  return (
    <section aria-label="研究质量" className="min-w-0 border border-border bg-[var(--surface)]">
      <div className="px-4 pt-4">
        <SectionHeader
          title="研究质量"
          description="仅在可计算分母存在时展示比率，不以零值替代缺失记录。"
        />
      </div>
      <div className="grid border-y border-border sm:grid-cols-2">
        <Metric
          label="候选保留率"
          value={quality.retentionRate === null ? undefined : `${Math.round(quality.retentionRate * 100)}%`}
          className="px-4 sm:border-r sm:border-border"
        />
        <Metric
          label="人工复核中位耗时"
          value={formatDuration(quality.medianHumanReviewSeconds)}
          className="border-t border-border px-4 sm:border-t-0"
        />
      </div>
      {model.empty ? (
        <PanelState state="empty" className="h-60" detail="当前记录不足以计算候选保留、反证淘汰和证据完整率。" />
      ) : (
        <div className="px-3 py-2">
          <EChartsCanvas
            option={model.option}
            label="候选保留率、反证淘汰率和证据完整率柱状图"
          />
        </div>
      )}
    </section>
  );
}
