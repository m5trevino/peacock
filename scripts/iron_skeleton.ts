import { PeacockEngine, PipelineStage } from '../src/core/PeacockEngine';
import * as readline from 'readline';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

const engine = new PeacockEngine();

async function ask(query: string): Promise<string> {
    return new Promise(resolve => rl.question(query, resolve));
}

async function main() {
    console.log("=== OPERATION IRON SKELETON v0.1 ===");
    console.log("Interactive CLI for Peacock Engine");

    const promptDir = path.resolve(__dirname, '../prompts');

    // Commands Loop
    while (true) {
        console.log('\n========================================');
        console.log(`STAGE: ${engine.activeStage.toUpperCase()}`);

        if (engine.lastCallMeta) {
            const since = engine.getTimeSinceLastStrike().toFixed(1);
            console.log(`PROXY: ${engine.lastCallMeta.ip} | KEY: ${engine.lastCallMeta.key} | ELAPSED: ${since}s`);
        } else {
            console.log(`PROXY: No strikes recorded.`);
        }
        console.log('----------------------------------------');

        const answer = await ask('COMMAND > ');

        const [cmd, arg] = answer.split(' ');

        if (!cmd) continue;

        try {
            switch (cmd) {
                case 'quit':
                    rl.close();
                    return;

                case 'stage':
                    if (Object.values(PipelineStage).includes(arg as PipelineStage)) {
                        engine.activeStage = arg as PipelineStage;
                        console.log(`Stage set to ${engine.activeStage}`);
                    } else {
                        console.log("Invalid stage. Options: spark, falcon, eagle, owl, hawk");
                    }
                    break;

                case 'load':
                    const input = await ask('Paste input (single line, or path): ');
                    engine.setInput(engine.activeStage, input);
                    console.log('Input set.');
                    break;

                case 'prompt':
                    const promptPath = path.join(promptDir, arg || `${engine.activeStage}.md`);
                    try {
                        await engine.loadPrompt(engine.activeStage, promptPath);
                    } catch {
                        const v21Path = path.join(promptDir, `${engine.activeStage}_v21.md`);
                        await engine.loadPrompt(engine.activeStage, v21Path);
                    }
                    break;

                case 'strike':
                    console.log("Executing strike...");
                    const res = await engine.executeStrike(engine.activeStage, arg);
                    console.log("--- RESPONSE START ---");
                    console.log(res.slice(0, 500) + "... [truncated]");
                    console.log("--- RESPONSE END ---");
                    break;

                case 'inspect':
                    console.log(`Input for ${engine.activeStage}:`);
                    console.log(engine.inputs[engine.activeStage]);
                    break;

                case 'queue':
                    console.log(`Owl Queue (${engine.owlQueue.length} files):`);
                    engine.owlQueue.forEach(f => {
                        const tel = f.status === 'success' ? ` | IP: ${f.ipUsed} | KEY: ${f.keyUsed}` : '';
                        console.log(`[${f.id}] ${f.path} - ${f.status}${tel}`);
                    });
                    break;

                case 'owl':
                    const [fileId, owlModel] = arg ? [arg, 'llama-3.1-8b-instant'] : [null, 'llama-3.1-8b-instant'];
                    if (arg === 'all') {
                        console.log("Striking ALL files in queue...");
                        for (const file of engine.owlQueue) {
                            if (file.status === 'success') continue;
                            console.log(`Implementing ${file.path}...`);
                            await engine.executeOwlStrike(file.id, owlModel);
                            console.log(`[SUCCESS] IP: ${file.ipUsed} | Key: ${file.keyUsed}`);
                        }
                    } else if (arg) {
                        console.log(`Implementing ${arg}...`);
                        await engine.executeOwlStrike(arg, owlModel);
                        const file = engine.owlQueue.find(f => f.id === arg);
                        if (file) console.log(`[SUCCESS] IP: ${file.ipUsed} | Key: ${file.keyUsed}`);
                    }
                    break;

                case 'deploy':
                    const script = engine.generateDeployScript();
                    console.log(script);
                    break;

                default:
                    console.log("Unknown command.");
            }
        } catch (e) {
            console.error("Error:", e);
        }
    }
}

main();
