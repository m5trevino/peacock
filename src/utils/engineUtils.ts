import { OwlFile } from '../types';

export const parseEagleResponse = (content: any): OwlFile[] => {
    const queue: OwlFile[] = [];

    // V21: Handle pre-parsed Object (from backend Pydantic model)
    if (typeof content === 'object' && content !== null) {
        if (content.files && Array.isArray(content.files)) {
            content.files.forEach((file: any, index: number) => {
                queue.push({
                    id: `owl_file_obj_${Date.now()}_${index}`,
                    path: file.path,
                    skeleton: file.skeleton,
                    directives: file.directives || "Follow standard implementation patterns.",
                    status: 'pending'
                });
            });
            console.log(`[ENGINE] Handled ${queue.length} files from Structured Object.`);
            return queue;
        }
    }

    // V21: Elite Recursive Parser
    const deepParse = (raw: any): any => {
        if (typeof raw !== 'string') return raw;
        try {
            const parsed = JSON.parse(raw);
            if (typeof parsed === 'string') return deepParse(parsed);
            return parsed;
        } catch (e) {
            const cleaned = raw.trim()
                .replace(/^```json\s*/, '')
                .replace(/\s*```$/, '')
                .replace(/\\n/g, '\n')
                .replace(/\\"/g, '"');
            try { return JSON.parse(cleaned); } catch (i) {
                const m = raw.match(/\{[\s\S]*\}/);
                if (m) { try { return JSON.parse(m[0]); } catch (r) { return null; } }
                return null;
            }
        }
    };

    const data = deepParse(content);

    if (data && data.files && Array.isArray(data.files)) {
        data.files.forEach((file: any, index: number) => {
            const rawPath = file.path || file.file_path || file.filepath || "unknown_node";
            const cleanPath = String(rawPath).replace(/[\\"]/g, '').trim();
            queue.push({
                id: `owl_file_${Date.now()}_${index}`,
                path: cleanPath,
                skeleton: file.skeleton || "",
                directives: file.directives || "Follow standard implementation patterns.",
                status: 'pending'
            });
        });
        console.log(`[ENGINE] Elite Parser: Handled ${queue.length} files.`);
        return queue;
    }

    const text = typeof content === 'string' ? content : JSON.stringify(content);

    // Strategy 1: Header + Block Mapping (The "Eagle Simulation" way)
    // Looking for: ### path/to/file \n ```(lang) \n code \n ```
    const headerRegex = /###\s+([^\n]+)\s+```[a-z]*\n([\s\S]*?)\n```/g;
    let headerMatch;
    while ((headerMatch = headerRegex.exec(text)) !== null) {
        queue.push({
            id: `owl_file_signal_${Date.now()}_${queue.length}`,
            path: headerMatch[1].trim().replace(/[\\"]/g, ''),
            skeleton: headerMatch[2],
            directives: "Flesh out per mission parameters.",
            status: 'pending'
        });
    }

    // Strategy 2: Legacy Regex fallback (EOF blocks)
    if (queue.length === 0) {
        const eofRegex = /mkdir -p ([\w\/.-]+)\s+cat << 'EOF' > ([\w\/.-]+)\s+([\s\S]+?)EOF/g;
        let match;
        while ((match = eofRegex.exec(text)) !== null) {
            queue.push({
                id: `owl_file_fallback_${Date.now()}_${queue.length}`,
                path: match[2].trim().replace(/[\\"]/g, ''),
                skeleton: match[3],
                directives: "Extracted from EOF block (Fallback Mode)",
                status: 'pending'
            });
        }
    }

    return queue;
};

/**
 * PROJECT NAME EXTRACTION
 */
export const extractProjectName = (rawInput: string): string => {
    if (!rawInput || typeof rawInput !== 'string') return `mission_${Date.now()}`;

    const trimmed = rawInput.trim();

    // Strategy 1: JSON Sniffing
    if (trimmed.startsWith('{')) {
        try {
            const parsed = JSON.parse(trimmed);
            const candidate = parsed.project || parsed.name || parsed.mission;
            if (candidate) return candidate.replace(/[^a-z0-9]/gi, '_').toLowerCase();
        } catch (e) {
            // Not valid JSON, proceed to line parsing
        }
    }

    // Strategy 2: Line Parsing
    const lines = trimmed.split('\n').map(l => l.trim()).filter(l => l.length > 0);
    for (const line of lines) {
        // Skip metadata lines that often lead to "___json" or similar
        if (line.toLowerCase().startsWith('###') || line.toLowerCase().startsWith('json')) continue;

        // Look for mission/project headers
        const headerMatch = line.match(/(?:mission|project|name):\s*(.+)/i);
        if (headerMatch && headerMatch[1]) {
            return headerMatch[1].trim().replace(/[^a-z0-9]/gi, '_').toLowerCase();
        }

        // Fallback to first non-empty / non-metadata line
        const clean = line
            .replace(/[^a-z0-9\s]/gi, '_')
            .replace(/\s+/g, '_')
            .replace(/app_name/gi, '')
            .replace(/project_name/gi, '')
            .replace(/^_+|_+$/g, '')
            .toLowerCase();

        if (clean && clean !== 'json' && clean.length > 2) return clean.substring(0, 32);
    }

    return `mission_${Date.now()}`;
};

/**
 * CODE CLEANER
 */
export const cleanStrikeContent = (content: string): string => {
    if (!content) return "";
    let cleaned = content.replace(/```[a-z]*\n/gi, '');
    cleaned = cleaned.replace(/\n```$/g, '');
    cleaned = cleaned.replace(/```$/g, '');
    return cleaned.trim();
};
