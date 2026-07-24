export {};

declare global {
  interface Window {
    __programRuleRefreshCalls: number;
    __recordMythosLabRequest: () => Promise<void>;
  }
}
