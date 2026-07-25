export {};

declare global {
  interface Window {
    __programRuleRefreshCalls: number;
    __recordMythosLabRequest: () => Promise<void>;
    __recordAutopilotEmergencyStopStep: (step: "local", campaignId: string) => Promise<void>;
  }
}
