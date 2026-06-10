import { consola } from 'consola';
import type { Finding, AIValidationResult } from '../types/finding.js';
import type { AIConfig } from '../types/config.js';

/**
 * AI Validator - Uses LLM to validate findings and reduce false positives
 *
 * This is an OPTIONAL feature (OFF by default).
 * When enabled, it sends code context and finding details to an LLM
 * to validate whether the finding is a true positive.
 */

export class AIValidator {
  private config: AIConfig;
  private enabled: boolean;

  constructor(config: AIConfig) {
    this.config = config;
    this.enabled = config.enabled && !!this.getApiKey();
  }

  /**
   * Check if AI validation is available
   */
  isAvailable(): boolean {
    return this.enabled;
  }

  /**
   * Validate a batch of findings using AI
   */
  async validateFindings(findings: Finding[]): Promise<Finding[]> {
    if (!this.enabled) return findings;

    const toValidate = findings.slice(0, this.config.maxFindings || 20);
    consola.info(`AI validating ${toValidate.length} findings...`);

    const validated: Finding[] = [];

    for (const finding of toValidate) {
      try {
        const result = await this.validateSingleFinding(finding);
        validated.push({
          ...finding,
          aiValidation: result,
        });
      } catch (error) {
        consola.debug(`AI validation failed for ${finding.id}:`, error);
        validated.push(finding);
      }
    }

    // Add remaining unvalidated findings
    for (let i = toValidate.length; i < findings.length; i++) {
      validated.push(findings[i]);
    }

    return validated;
  }

  /**
   * Validate a single finding
   */
  private async validateSingleFinding(finding: Finding): Promise<AIValidationResult> {
    const prompt = this.buildPrompt(finding);

    try {
      const response = await this.callLLM(prompt);
      return this.parseResponse(response);
    } catch (error) {
      consola.debug('LLM call failed:', error);
      return {
        isValid: true,
        explanation: 'AI validation unavailable - treating as valid finding',
        confidence: 0,
      };
    }
  }

  /**
   * Build the LLM prompt for finding validation
   */
  private buildPrompt(finding: Finding): string {
    return `You are a security code reviewer. Analyze the following code finding and determine if it is a TRUE POSITIVE (real vulnerability/issue) or FALSE POSITIVE (not actually a problem).

**Finding:**
- Rule: ${finding.ruleId}
- Title: ${finding.title}
- Severity: ${finding.severity}
- Category: ${finding.category}
- Message: ${finding.message}

**Code:**
File: ${finding.location.file} (line ${finding.location.startLine})
\`\`\`
${finding.location.snippet}
\`\`\`

${finding.taintFlow ? `**Data Flow:**\n${finding.taintFlow.map(s => `${s.kind}: ${s.label} (${s.location.file}:${s.location.startLine})`).join('\n')}` : ''}

${finding.context ? `**Context:** This code is in a ${finding.context.type} context` : ''}

**Respond in JSON format:**
{
  "isValid": true/false,
  "explanation": "Brief explanation of why this is or isn't a real issue",
  "confidence": 0.0-1.0,
  "fixSuggestion": "Optional: how to fix if it's a real issue"
}`;
  }

  /**
   * Call the LLM API
   */
  private async callLLM(prompt: string): Promise<string> {
    const apiKey = this.getApiKey();
    if (!apiKey) {
      throw new Error('No API key configured for AI validation');
    }

    switch (this.config.provider) {
      case 'openai':
        return this.callOpenAI(prompt, apiKey);
      case 'anthropic':
        return this.callAnthropic(prompt, apiKey);
      case 'ollama':
        return this.callOllama(prompt);
      default:
        throw new Error(`Unknown AI provider: ${this.config.provider}`);
    }
  }

  /**
   * Call OpenAI API
   */
  private async callOpenAI(prompt: string, apiKey: string): Promise<string> {
    const baseUrl = this.config.baseUrl || 'https://api.openai.com/v1';
    const model = this.config.model || 'gpt-4o-mini';

    const response = await fetch(`${baseUrl}/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model,
        messages: [
          { role: 'system', content: 'You are a security code reviewer. Respond only in valid JSON.' },
          { role: 'user', content: prompt },
        ],
        temperature: this.config.temperature || 0.1,
        max_tokens: 500,
      }),
    });

    if (!response.ok) {
      throw new Error(`OpenAI API error: ${response.status} ${response.statusText}`);
    }

    const data = await response.json() as { choices: Array<{ message: { content: string } }> };
    return data.choices[0]?.message?.content || '';
  }

  /**
   * Call Anthropic API
   */
  private async callAnthropic(prompt: string, apiKey: string): Promise<string> {
    const baseUrl = this.config.baseUrl || 'https://api.anthropic.com/v1';
    const model = this.config.model || 'claude-3-haiku-20240307';

    const response = await fetch(`${baseUrl}/messages`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model,
        max_tokens: 500,
        messages: [{ role: 'user', content: prompt }],
        temperature: this.config.temperature || 0.1,
      }),
    });

    if (!response.ok) {
      throw new Error(`Anthropic API error: ${response.status} ${response.statusText}`);
    }

    const data = await response.json() as { content: Array<{ text: string }> };
    return data.content[0]?.text || '';
  }

  /**
   * Call Ollama local API
   */
  private async callOllama(prompt: string): Promise<string> {
    const baseUrl = this.config.baseUrl || 'http://localhost:11434';
    const model = this.config.model || 'llama3';

    const response = await fetch(`${baseUrl}/api/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model,
        prompt,
        stream: false,
        options: { temperature: this.config.temperature || 0.1 },
      }),
    });

    if (!response.ok) {
      throw new Error(`Ollama API error: ${response.status}`);
    }

    const data = await response.json() as { response: string };
    return data.response || '';
  }

  /**
   * Parse LLM response into validation result
   */
  private parseResponse(response: string): AIValidationResult {
    try {
      // Extract JSON from response (may be wrapped in markdown code blocks)
      const jsonMatch = response.match(/\{[\s\S]*\}/);
      if (!jsonMatch) {
        return {
          isValid: true,
          explanation: 'Could not parse AI response',
          confidence: 0,
        };
      }

      const parsed = JSON.parse(jsonMatch[0]);
      return {
        isValid: parsed.isValid ?? true,
        explanation: parsed.explanation || 'No explanation provided',
        confidence: typeof parsed.confidence === 'number' ? parsed.confidence : 0.5,
        fixSuggestion: parsed.fixSuggestion,
      };
    } catch {
      return {
        isValid: true,
        explanation: 'AI response parsing failed',
        confidence: 0,
      };
    }
  }

  /**
   * Get API key from config or environment
   */
  private getApiKey(): string | undefined {
    if (this.config.apiKey) return this.config.apiKey;

    switch (this.config.provider) {
      case 'openai':
        return process.env.OPENAI_API_KEY;
      case 'anthropic':
        return process.env.ANTHROPIC_API_KEY;
      case 'ollama':
        return 'local'; // Ollama doesn't need an API key
      default:
        return undefined;
    }
  }
}
