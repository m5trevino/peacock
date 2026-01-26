
import { GoogleGenAI } from "@google/genai";

// Initialize the Google GenAI client with the API key from environment variables.
const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });

export const performIntelligentMerge = async (
  template: string,
  newData: string,
  instruction: string
): Promise<string> => {
  try {
    const response = await ai.models.generateContent({
      model: 'gemini-3-flash-preview',
      contents: `
        SYSTEM INSTRUCTION: You are "The Architect," a high-performance cognitive processor specializing in structural text integration.
        
        TASK: Intelligently merge NEW DATA into a SOURCE TEMPLATE based on the provided STRATEGIC INSTRUCTION.
        
        STRATEGIC INSTRUCTION:
        ${instruction}

        SOURCE TEMPLATE (The Blueprint):
        """
        ${template}
        """

        NEW DATA (The Payload):
        """
        ${newData}
        """

        OPERATIONAL RULES:
        1. IDENTIFY THE RIGHT SPOT: Look for placeholders like [Pending Merge], [REQUIREMENTS_CONTENT_HERE], or logical thematic breaks where the new data strengthens the narrative.
        2. MAINTAIN STRUCTURE: Do not delete the fundamental headers or organizational hierarchy of the SOURCE TEMPLATE unless explicitly instructed.
        3. SYNCHRONIZE: Adapt the language of the NEW DATA to match the tone of the SOURCE TEMPLATE if necessary.
        4. NO CHATTER: Return ONLY the final, merged, and polished text. No introductions or explanations.
      `,
    });

    return response.text || "Error: System failed to generate merged output.";
  } catch (error) {
    console.error("Gemini Merge Error:", error);
    throw error;
  }
};
