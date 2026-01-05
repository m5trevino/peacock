import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import fs from 'fs';
import path from 'path';
import axios from 'axios';
import { GoogleGenAI } from '@google/genai';
import { HttpsProxyAgent } from 'https-proxy-agent';

// Load environment variables
dotenv.config({ path: '.env.local' });

// ============================================================ 
// 🎲 KEY ROTATION SYSTEM (PORTED FROM AI-HANDLER)
// ============================================================ 
interface KeyAsset { label: string; account: string; key: string; }

class KeyPool {
  private deck: KeyAsset[] = [];
  private pointer: number = 0;
  private type: string;

  constructor(envString: string | undefined, type: string) {
    this.type = type;
    if (!envString) return;
    const entries = envString.split(',');
    entries.forEach((entry, idx) => {
      let label = "", key = "";
      if (entry.includes(':')) {
        const parts = entry.split(':');
        label = parts[0]; key = parts[1];
      } else {
        label = `${type}_DEALER_${String(idx + 1).padStart(2, '0')}`;
        key = entry;
      }
      this.deck.push({ label: label.trim(), account: label.trim(), key: key.trim() });
    });
    this.shuffle();
  }

  private shuffle() {
    if (this.deck.length === 0) return;
    for (let i = this.deck.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [this.deck[i], this.deck[j]] = [this.deck[j], this.deck[i]];
    }
    this.pointer = 0;
  }

  public getNext(): KeyAsset {
    if (this.deck.length === 0) throw new Error(`NO AMMUNITION FOR ${this.type}`);
    const asset = this.deck[this.pointer];
    this.pointer++;
    if (this.pointer >= this.deck.length) this.shuffle();
    return asset;
  }
}

// Instantiate pools (using common env names or fallbacks)
const GooglePool = new KeyPool(process.env.GOOGLE_KEYS || process.env.GEMINI_API_KEY, 'GOOGLE');
const GroqPool = new KeyPool(process.env.GROQ_KEYS, 'GROQ');
const DeepSeekPool = new KeyPool(process.env.DEEPSEEK_KEYS, 'DEEPSEEK');
const MistralPool = new KeyPool(process.env.MISTRAL_KEYS, 'MISTRAL');

// ============================================================ 
// 🧠 ENGINE CONFIG
// ============================================================ 
const app = express();
const PORT = 8888;
const proxyUrl = process.env.PROXY_URL;
const agent = (process.env.PROXY_ENABLED === 'true' && proxyUrl) ? new HttpsProxyAgent(proxyUrl) : undefined;

app.use(cors());
app.use(express.json({ limit: '50mb' }));

const AMMO_DIR = '/home/flintx/ammo';
const PROMPTS_DIR = '/home/flintx/prompts';

// ============================================================ 
// ⚡ ENDPOINTS
// ============================================================ 

// 1. Model Registry
app.get('/v1/models', (req, res) => {
  res.json([
    { id: "gemini-2.0-flash", gateway: "google", tier: "cheap", note: "Gemini 2.0 Flash" },
    { id: "gemini-1.5-pro", gateway: "google", tier: "expensive", note: "Gemini 1.5 Pro" },
    { id: "llama-3.3-70b-versatile", gateway: "groq", tier: "cheap", note: "Llama 3.3 70B" },
    { id: "deepseek-chat", gateway: "deepseek", tier: "cheap", note: "DeepSeek V3" }
  ]);
});

// 2. Strike Execution
app.post('/v1/strike', async (req, res) => {
  const { modelId, prompt, temp = 0.7 } = req.body;
  console.log(`[STRIKE] ${modelId} | ${new Date().toLocaleTimeString()}`);

  try {
    // Determine Gateway (simplified logic)
    let gateway = 'google';
    if (modelId.includes('llama')) gateway = 'groq';
    if (modelId.includes('deepseek')) gateway = 'deepseek';
    if (modelId.includes('mistral')) gateway = 'mistral';

    if (gateway === 'google') {
      const asset = GooglePool.getNext();
      const genAI = new GoogleGenAI(asset.key);
      const model = genAI.getGenerativeModel({ model: modelId });
      const result = await model.generateContent({
        contents: [{ role: 'user', parts: [{ text: prompt }] }],
        generationConfig: { temperature: temp }
      });
      const response = await result.response;
      return res.json({ content: response.text() });
    }

    if (gateway === 'groq') {
      const asset = GroqPool.getNext();
      const response = await axios.post('https://api.groq.com/openai/v1/chat/completions', {
        model: modelId,
        messages: [{ role: 'user', content: prompt }],
        temperature: temp
      }, {
        headers: { 'Authorization': `Bearer ${asset.key}` },
        httpsAgent: agent
      });
      return res.json({ content: response.data.choices[0].message.content });
    }

    // Add other gateways as needed...
    throw new Error(`Gateway ${gateway} implementation pending.`);

  } catch (error: any) {
    console.error("Strike Failed:", error.message);
    res.status(500).json({ error: error.message });
  }
});

// 3. Filesystem: Ammo
app.get('/v1/fs/ammo', (req, res) => {
  if (!fs.existsSync(AMMO_DIR)) return res.json([]);
  const files = fs.readdirSync(AMMO_DIR).filter(f => f.endsWith('.md') || f.endsWith('.txt') || f.endsWith('.json'));
  res.json(files);
});

app.get('/v1/fs/ammo/:name', (req, res) => {
  const filePath = path.join(AMMO_DIR, req.params.name);
  if (!fs.existsSync(filePath)) return res.status(404).send("File not found");
  res.json({ content: fs.readFileSync(filePath, 'utf-8') });
});

// 4. Filesystem: Prompts
app.get('/v1/fs/prompts', (req, res) => {
  if (!fs.existsSync(PROMPTS_DIR)) return res.json([]);
  const files = fs.readdirSync(PROMPTS_DIR).filter(f => f.endsWith('.md') || f.endsWith('.txt'));
  const prompts = files.map(f => ({
    id: path.parse(f).name,
    content: fs.readFileSync(path.join(PROMPTS_DIR, f), 'utf-8')
  }));
  res.json(prompts);
});

app.post('/v1/fs/prompts', (req, res) => {
  const { id, content } = req.body;
  const filePath = path.join(PROMPTS_DIR, `${id}.md`);
  fs.writeFileSync(filePath, content);
  res.sendStatus(200);
});

app.listen(PORT, () => {
  console.log(`⚡ Peacock Omega Engine active on http://localhost:${PORT}`);
  console.log(`📁 Ammo: ${AMMO_DIR}`);
  console.log(`📁 Prompts: ${PROMPTS_DIR}`);
});