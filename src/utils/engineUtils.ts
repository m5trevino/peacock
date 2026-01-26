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

    // Convert to string for regex strategies if not an object
    const strContent = typeof content === 'string' ? content : JSON.stringify(content);

    try {
        // Strategy 1: Find JSON block (strips markdown ```json wrapper if present)
        const jsonMatch = strContent.match(/\{[\s\S]*\}/);

        // Attempt to parse if match found, or try raw content
        const jsonString = jsonMatch ? jsonMatch[0] : content;
        const data = JSON.parse(jsonString);

        if (data.files && Array.isArray(data.files)) {
            data.files.forEach((file: any, index: number) => {
                queue.push({
                    id: `owl_file_${Date.now()}_${index}`,
                    path: file.path,
                    skeleton: file.skeleton,
                    directives: file.directives || "Follow standard implementation patterns.",
                    status: 'pending'
                });
            });
            console.log(`[ENGINE] Successfully parsed ${queue.length} files from JSON.`);
            return queue;
        }
    } catch (error) {
        console.warn('[ENGINE] JSON Parsing failed, attempting fallback strategies...', error);
    }

    // Strategy 2: Fallback to Regex for Files (if JSON fails)
    // Matches: { "path": "...", "skeleton": "...", ... } objects loosely
    // This is less reliable but catches partial JSON streams
    if (queue.length === 0) {
        console.warn('[ENGINE] Attempting legacy EOF regex fallback...');
        const eofRegex = /mkdir -p ([\w\/.-]+)\s+cat << 'EOF' > ([\w\/.-]+)\s+([\s\S]+?)EOF/g;
        let match;
        let count = 0;

        while ((match = eofRegex.exec(content)) !== null) {
            queue.push({
                id: `owl_file_fallback_${Date.now()}_${count++}`,
                path: match[2].trim(),
                skeleton: match[3],
                directives: "Extracted from EOF block (Fallback Mode)",
                status: 'pending'
            });
        }
    }

    return queue;
};
