export interface ServerLlmConfig {
  provider: string;
  model: string;
  apiKey: string;
  baseUrl: string;
}

export function getServerLlmConfig(): ServerLlmConfig | null {
  const apiKey = process.env.SCANNER_LLM_API_KEY?.trim();
  if (!apiKey) {
    return null;
  }

  return {
    provider: process.env.SCANNER_LLM_PROVIDER?.trim() || "openai-compatible",
    model: process.env.SCANNER_LLM_MODEL?.trim() || "gpt-4.1-mini",
    apiKey,
    baseUrl: process.env.SCANNER_LLM_BASE_URL?.trim() || "https://api.openai.com/v1"
  };
}
