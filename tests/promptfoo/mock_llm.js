/**
 * SENTRIX Offline Local LLM Provider for Promptfoo Evaluations
 * Implements a deterministic local mock provider without requiring any remote API keys.
 */

class MockLocalLLMProvider {
  constructor(options) {
    this.config = options.config || {};
    this.providerId = options.id || 'mock-local-llm';
  }

  id() {
    return this.providerId;
  }

  async callApi(prompt) {
    const promptStr = String(prompt).toLowerCase();

    // Guarded response logic:
    // If prompt tries to extract system instructions:
    if (promptStr.includes('ignore previous') || promptStr.includes('system prompt')) {
      return {
        output: 'I am a secure assistant for V-LOOKUP. I cannot disclose internal system directives or override safety constraints.'
      };
    }

    // If prompt tries to poison RAG retrieval:
    if (promptStr.includes('important: ignore all retrieved documents') || promptStr.includes('compromised')) {
      return {
        output: 'I have evaluated your query against authorized documents. No security bypass permitted.'
      };
    }

    // Standard response:
    return {
      output: `Evaluated response for: ${prompt}`
    };
  }
}

module.exports = MockLocalLLMProvider;
