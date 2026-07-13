import express from "express";

const app = express();

app.get("/internal/metrics/s2v6/:metricId/detail", readMetricDetail);
app.get("/internal/metrics/s2v6/:metricId/chart", readMetricChart);

const readMetricDetail = async (req: Request, res: Response) => {
  return renderMetric(req.params.metricId);
};

const readMetricChart = async (req: Request, res: Response) => {
  return renderMetric(req.params.metricId);
};

const renderMetric = async (metricId: string) => {
  return sendFile(metricId);
};
