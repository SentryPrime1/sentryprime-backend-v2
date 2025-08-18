// OpenAI Integration Service
// Handles AI-powered alt text generation using OpenAI's vision models

import OpenAI from 'openai';

export class OpenAIService {
  constructor(config = {}) {
    this.config = {
      apiKey: config.apiKey || process.env.OPENAI_API_KEY,
      model: config.model || 'gpt-4o-mini',
      maxTokens: config.maxTokens || 300,
      temperature: config.temperature || 0.3,
      maxRetries: config.maxRetries || 3,
      timeout: config.timeout || 30000,
      ...config
    };
    
    if (!this.config.apiKey) {
      console.warn('OpenAI API key not configured');
      this.client = null;
    } else {
      this.client = new OpenAI({
        apiKey: this.config.apiKey,
        timeout: this.config.timeout,
        maxRetries: this.config.maxRetries
      });
    }
    
    // Track API usage
    this.usage = {
      requests: 0,
      tokens: 0,
      errors: 0,
      lastRequest: null
    };
  }

  /**
   * Generate alt text suggestions for an image
   * @param {Object} imageInfo - Image information and data
   * @param {Object} context - Page context and options
   * @returns {Promise<Object>} Alt text suggestions
   */
  async generateAltTextSuggestions(imageInfo, context = {}) {
    if (!this.client) {
      throw new Error('OpenAI API not configured');
    }
    
    try {
      console.log(`Generating alt text for image: ${imageInfo.url}`);
      
      // Prepare image data for OpenAI
      const imageData = this.prepareImageData(imageInfo);
      
      // Build context-aware prompt
      const prompt = this.buildPrompt(imageInfo, context);
      
      // Make API request
      const response = await this.client.chat.completions.create({
        model: this.config.model,
        max_tokens: this.config.maxTokens,
        temperature: this.config.temperature,
        messages: [
          {
            role: 'system',
            content: this.getSystemPrompt()
          },
          {
            role: 'user',
            content: [
              {
                type: 'text',
                text: prompt
              },
              {
                type: 'image_url',
                image_url: {
                  url: imageData,
                  detail: 'auto'
                }
              }
            ]
          }
        ]
      });
      
      // Update usage tracking
      this.updateUsageStats(response);
      
      // Parse and validate response
      const suggestions = this.parseResponse(response, context);
      
      console.log(`Generated ${suggestions.suggestions.length} alt text suggestions`);
      
      return suggestions;
      
    } catch (error) {
      this.usage.errors++;
      console.error('OpenAI API request failed:', error);
      
      // Provide fallback suggestions
      return this.getFallbackSuggestions(imageInfo, context, error);
    }
  }

  /**
   * Prepare image data for OpenAI API
   * @private
   */
  prepareImageData(imageInfo) {
    // If we have image data as buffer, convert to base64 data URL
    if (imageInfo.data && Buffer.isBuffer(imageInfo.data)) {
      const mimeType = imageInfo.contentType || 'image/jpeg';
      const base64 = imageInfo.data.toString('base64');
      return `data:${mimeType};base64,${base64}`;
    }
    
    // Otherwise use the image URL directly
    return imageInfo.url;
  }

  /**
   * Build context-aware prompt for alt text generation
   * @private
   */
  buildPrompt(imageInfo, context) {
    let prompt = 'Generate 3 different alt text descriptions for this image. ';
    
    // Add page context
    if (context.pageTitle) {
      prompt += `This image appears on a webpage titled "${context.pageTitle}". `;
    }
    
    if (context.pageContext) {
      try {
        const pageInfo = JSON.parse(context.pageContext);
        if (pageInfo.description) {
          prompt += `Page description: "${pageInfo.description}". `;
        }
      } catch (e) {
        // Ignore JSON parse errors
      }
    }
    
    // Add existing alt text if available
    if (context.existingAlt && context.existingAlt.trim()) {
      prompt += `Current alt text: "${context.existingAlt}". `;
    }
    
    // Add image features context
    if (imageInfo.features) {
      const features = imageInfo.features;
      if (features.isSmall) {
        prompt += 'This is a small image, likely an icon or decorative element. ';
      }
      if (features.likelyDecorative) {
        prompt += 'This image may be decorative. ';
      }
    }
    
    // Add specific instructions
    prompt += `
Please provide:
1. A concise, descriptive alt text (recommended)
2. A detailed alt text with more context
3. A brief alt text focusing on essential information

For each suggestion, also indicate:
- Confidence level (0.0 to 1.0)
- Whether the image appears to be decorative

Format your response as JSON:
{
  "suggestions": [
    {
      "text": "alt text here",
      "confidence": 0.9,
      "type": "concise"
    },
    {
      "text": "detailed alt text here", 
      "confidence": 0.8,
      "type": "detailed"
    },
    {
      "text": "brief alt text here",
      "confidence": 0.85,
      "type": "brief"
    }
  ],
  "isDecorative": false,
  "reasoning": "Brief explanation of the analysis"
}

Guidelines:
- Keep alt text under 125 characters when possible
- Focus on the image's purpose and content, not just appearance
- Avoid starting with "Image of" or "Picture of"
- Consider the context of the webpage
- If decorative, suggest empty alt text (alt="")
`;
    
    return prompt;
  }

  /**
   * Get system prompt for alt text generation
   * @private
   */
  getSystemPrompt() {
    return `You are an expert accessibility consultant specializing in creating alt text for images on websites. Your goal is to help make web content accessible to users with visual impairments by providing meaningful, context-appropriate alternative text descriptions.

Key principles:
1. Alt text should convey the meaning and function of the image, not just describe its appearance
2. Consider the context in which the image appears
3. Be concise but informative
4. Avoid redundancy with surrounding text
5. Identify truly decorative images that should have empty alt text
6. Focus on what's important for understanding the content or completing tasks

You have expertise in:
- Web accessibility standards (WCAG)
- Screen reader technology
- User experience for people with disabilities
- Content strategy and information architecture`;
  }

  /**
   * Parse OpenAI response and validate suggestions
   * @private
   */
  parseResponse(response, context) {
    try {
      const content = response.choices[0]?.message?.content;
      if (!content) {
        throw new Error('Empty response from OpenAI');
      }
      
      // Try to parse JSON response
      let parsed;
      try {
        // Extract JSON from response (in case there's extra text)
        const jsonMatch = content.match(/\{[\s\S]*\}/);
        if (jsonMatch) {
          parsed = JSON.parse(jsonMatch[0]);
        } else {
          parsed = JSON.parse(content);
        }
      } catch (parseError) {
        // If JSON parsing fails, create structured response from text
        parsed = this.parseTextResponse(content);
      }
      
      // Validate and normalize suggestions
      const suggestions = this.validateSuggestions(parsed.suggestions || []);
      
      return {
        suggestions,
        isDecorative: parsed.isDecorative || false,
        reasoning: parsed.reasoning || 'AI analysis completed',
        model: this.config.model,
        generatedAt: new Date().toISOString()
      };
      
    } catch (error) {
      console.error('Failed to parse OpenAI response:', error);
      throw new Error(`Response parsing failed: ${error.message}`);
    }
  }

  /**
   * Parse text response when JSON parsing fails
   * @private
   */
  parseTextResponse(content) {
    const suggestions = [];
    
    // Try to extract alt text suggestions from text
    const lines = content.split('\n').filter(line => line.trim());
    
    for (const line of lines) {
      // Look for numbered suggestions or bullet points
      const match = line.match(/^\d+\.?\s*(.+)$/) || line.match(/^[-*]\s*(.+)$/);
      if (match && suggestions.length < 3) {
        suggestions.push({
          text: match[1].trim().replace(/^["']|["']$/g, ''), // Remove quotes
          confidence: 0.7,
          type: suggestions.length === 0 ? 'concise' : suggestions.length === 1 ? 'detailed' : 'brief'
        });
      }
    }
    
    // If no structured suggestions found, use the entire content as one suggestion
    if (suggestions.length === 0) {
      suggestions.push({
        text: content.trim().slice(0, 125),
        confidence: 0.6,
        type: 'concise'
      });
    }
    
    return {
      suggestions,
      isDecorative: content.toLowerCase().includes('decorative') || content.toLowerCase().includes('alt=""'),
      reasoning: 'Parsed from text response'
    };
  }

  /**
   * Validate and normalize suggestions
   * @private
   */
  validateSuggestions(suggestions) {
    const validated = [];
    
    for (const suggestion of suggestions) {
      if (!suggestion || typeof suggestion !== 'object') {
        continue;
      }
      
      const text = (suggestion.text || '').trim();
      if (!text || text.length > 250) {
        continue; // Skip empty or too long suggestions
      }
      
      validated.push({
        text,
        confidence: Math.max(0, Math.min(1, suggestion.confidence || 0.7)),
        type: suggestion.type || 'general'
      });
    }
    
    // Ensure we have at least one suggestion
    if (validated.length === 0) {
      validated.push({
        text: 'Image content could not be analyzed',
        confidence: 0.3,
        type: 'fallback'
      });
    }
    
    return validated;
  }

  /**
   * Get fallback suggestions when API fails
   * @private
   */
  getFallbackSuggestions(imageInfo, context, error) {
    console.log('Providing fallback alt text suggestions');
    
    const suggestions = [];
    
    // Basic fallback based on image features
    if (imageInfo.features) {
      const features = imageInfo.features;
      
      if (features.likelyDecorative || features.isSmall) {
        suggestions.push({
          text: '',
          confidence: 0.6,
          type: 'decorative'
        });
      }
      
      if (features.isLarge) {
        suggestions.push({
          text: 'Large image content',
          confidence: 0.4,
          type: 'generic'
        });
      }
    }
    
    // Context-based fallback
    if (context.existingAlt && context.existingAlt.trim()) {
      suggestions.push({
        text: context.existingAlt.trim(),
        confidence: 0.5,
        type: 'existing'
      });
    }
    
    // Generic fallback
    if (suggestions.length === 0) {
      suggestions.push({
        text: 'Image requires manual alt text',
        confidence: 0.3,
        type: 'fallback'
      });
    }
    
    return {
      suggestions,
      isDecorative: false,
      reasoning: `Fallback suggestions due to API error: ${error.message}`,
      model: 'fallback',
      generatedAt: new Date().toISOString(),
      error: error.message
    };
  }

  /**
   * Update usage statistics
   * @private
   */
  updateUsageStats(response) {
    this.usage.requests++;
    this.usage.lastRequest = new Date();
    
    if (response.usage) {
      this.usage.tokens += response.usage.total_tokens || 0;
    }
  }

  /**
   * Get API usage statistics
   */
  getUsageStats() {
    return {
      ...this.usage,
      averageTokensPerRequest: this.usage.requests > 0 ? Math.round(this.usage.tokens / this.usage.requests) : 0,
      errorRate: this.usage.requests > 0 ? (this.usage.errors / this.usage.requests * 100).toFixed(2) + '%' : '0%'
    };
  }

  /**
   * Test API connectivity
   */
  async testConnection() {
    if (!this.client) {
      throw new Error('OpenAI API not configured');
    }
    
    try {
      // Simple test request
      const response = await this.client.chat.completions.create({
        model: this.config.model,
        max_tokens: 10,
        messages: [
          {
            role: 'user',
            content: 'Test connection. Respond with "OK".'
          }
        ]
      });
      
      return {
        status: 'connected',
        model: this.config.model,
        response: response.choices[0]?.message?.content || 'No response'
      };
      
    } catch (error) {
      throw new Error(`Connection test failed: ${error.message}`);
    }
  }

  /**
   * Get service health status
   */
  async getHealthStatus() {
    try {
      if (!this.client) {
        return {
          status: 'unavailable',
          reason: 'API key not configured'
        };
      }
      
      // Test connection
      await this.testConnection();
      
      return {
        status: 'healthy',
        model: this.config.model,
        usage: this.getUsageStats(),
        config: {
          maxTokens: this.config.maxTokens,
          temperature: this.config.temperature,
          timeout: this.config.timeout
        }
      };
      
    } catch (error) {
      return {
        status: 'unhealthy',
        error: error.message,
        usage: this.getUsageStats()
      };
    }
  }

  /**
   * Estimate cost for processing images
   */
  estimateCost(imageCount, options = {}) {
    // Rough cost estimation based on OpenAI pricing
    // These are approximate values and should be updated based on current pricing
    const costs = {
      'gpt-4o-mini': {
        inputTokens: 0.00015 / 1000, // per token
        outputTokens: 0.0006 / 1000, // per token
        imageTokens: 85 // tokens per image (approximate)
      }
    };
    
    const modelCost = costs[this.config.model] || costs['gpt-4o-mini'];
    const avgInputTokens = 200; // Average prompt tokens
    const avgOutputTokens = this.config.maxTokens * 0.7; // Assume 70% of max tokens used
    
    const totalInputTokens = imageCount * (avgInputTokens + modelCost.imageTokens);
    const totalOutputTokens = imageCount * avgOutputTokens;
    
    const estimatedCost = (totalInputTokens * modelCost.inputTokens) + (totalOutputTokens * modelCost.outputTokens);
    
    return {
      imageCount,
      estimatedCost: Math.round(estimatedCost * 100) / 100, // Round to 2 decimal places
      currency: 'USD',
      breakdown: {
        inputTokens: totalInputTokens,
        outputTokens: totalOutputTokens,
        inputCost: totalInputTokens * modelCost.inputTokens,
        outputCost: totalOutputTokens * modelCost.outputTokens
      }
    };
  }
}
