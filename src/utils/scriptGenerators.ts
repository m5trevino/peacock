import { OwlFile } from '../types';

export const generateScaffoldScript = (files: OwlFile[]) => {
    let script = "#!/bin/bash\n\n";
    const dirs = [...new Set(files.map(f => f.path.split('/').slice(0, -1).join('/')))].filter(d => d !== "");
    dirs.forEach(d => script += `mkdir -p "${d}"\n`);
    files.forEach(f => {
        script += `\ncat << 'PEACOCK_EOF' > ${f.path}\n${f.skeleton}\n\n/* 
DNA_CONTRACT:\n${f.directives}\n*/\nPEACOCK_EOF\n`;
    });
    return script;
};

export const generateOverwriteScript = (path: string, content: string) => {
    const dir = path.split('/').slice(0, -1).join('/');

    // V21 SMART DETECT: If content already has heredoc, don't wrap it.
    if (content.trim().startsWith('mkdir') || content.includes('cat <<')) {
        return content;
    }

    return `mkdir -p "${dir}"\nchmod 755 "${dir}"\ncat << 'PEACOCK_EOF' > ${path}\n${content}\nPEACOCK_EOF\nchmod 644 ${path}`;
};

export const generateFullDeployScript = (files: OwlFile[]) => {
    let script = "#!/bin/bash\n\n# PEACOCK V21 AUTO-DEPLOY\n# PROJECT: CASEFLOW_PRO (INFERRED)\n\n";

    files.filter(f => f.status === 'completed').forEach(f => {
        const dir = f.path.split('/').slice(0, -1).join('/');

        // V21 SMART DETECT: If content is already a script, append it directly.
        if (f.output && (f.output.includes('cat <<') || f.output.includes('mkdir -p'))) {
            script += `\n# --- ${f.path} ---\n${f.output}\n\n`;
        } else {
            // Legacy/Fallback Wrapping
            script += `mkdir -p "${dir}"\nchmod 755 "${dir}"\ncat << 'PEACOCK_EOF' > ${f.path}\n${f.output}\nPEACOCK_EOF\nchmod 644 ${f.path}\n\n`;
        }
    });

    script += "\n\necho '[✅] DEPLOYMENT COMPLETE'\n";
    return script;
};
