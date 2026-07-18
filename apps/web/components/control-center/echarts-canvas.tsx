"use client";

import { BarChart } from "echarts/charts";
import { GridComponent, TooltipComponent } from "echarts/components";
import * as echarts from "echarts/core";
import type { EChartsCoreOption } from "echarts/core";
import { CanvasRenderer } from "echarts/renderers";
import { useEffect, useRef } from "react";

import { cn } from "@/lib/utils";

echarts.use([BarChart, GridComponent, TooltipComponent, CanvasRenderer]);

interface EChartsCanvasProps {
  option: EChartsCoreOption;
  className?: string;
  label: string;
}

export default function EChartsCanvas({ option, className, label }: EChartsCanvasProps) {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const container = containerRef.current;
    if (!container || container.clientWidth === 0 || container.clientHeight === 0) {
      return;
    }

    const chart = echarts.init(container, undefined, { renderer: "canvas" });
    chart.setOption(option, { notMerge: true });
    const observer = new ResizeObserver(() => {
      if (container.clientWidth > 0 && container.clientHeight > 0) {
        chart.resize();
      }
    });
    observer.observe(container);

    return () => {
      observer.disconnect();
      chart.dispose();
    };
  }, [option]);

  return (
    <div
      ref={containerRef}
      role="img"
      aria-label={label}
      className={cn("h-60 min-h-60 w-full min-w-0", className)}
    />
  );
}
