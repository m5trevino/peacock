
import React, { useEffect, useState } from 'react';
import { api } from '../../services/api';
import { audioService } from '../../services/audioService';

interface StartFileSelectorProps {
    onSelect: (content: string) => void;
}

export const StartFileSelector: React.FC<StartFileSelectorProps> = ({ onSelect }) => {
    const [files, setFiles] = useState<string[]>([]);
    const [loading, setLoading] = useState(false);
    const [isOpen, setIsOpen] = useState(false);

    useEffect(() => {
        if (isOpen) {
            setLoading(true);
            api.fetchStartFiles()
                .then(f => setFiles(f))
                .catch(err => console.error(err))
                .finally(() => setLoading(false));
        }
    }, [isOpen]);

    const handleFileClick = async (fileName: string) => {
        try {
            setLoading(true);
            const content = await api.fetchStartFile(fileName);
            onSelect(content);
            audioService.playSuccess();
            setIsOpen(false);
        } catch (e) {
            console.error(e);
            audioService.playError();
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="relative">
            <button
                onClick={() => setIsOpen(!isOpen)}
                className="px-4 py-2 bg-white/5 border border-white/10 rounded text-xs font-bold text-muted hover:text-white uppercase tracking-wider transition-colors flex items-center gap-2"
            >
                <span>📂</span> {isOpen ? 'CLOSE_INTEL' : 'LOAD_START_FILE'}
            </button>

            {isOpen && (
                <div className="absolute top-full left-0 mt-2 w-64 bg-black/90 border border-white/20 rounded-xl p-2 z-50 shadow-xl backdrop-blur-md max-h-60 overflow-y-auto custom-scrollbar">
                    {loading ? (
                        <div className="p-4 text-center text-xs text-muted animate-pulse">SCANNING_DIR...</div>
                    ) : files.length === 0 ? (
                        <div className="p-4 text-center text-xs text-white/30">NO_FILES_FOUND</div>
                    ) : (
                        <div className="flex flex-col gap-1">
                            {files.map(f => (
                                <button
                                    key={f}
                                    onClick={() => handleFileClick(f)}
                                    className="text-left px-3 py-2 rounded hover:bg-white/10 text-xs font-mono text-white/70 hover:text-white truncate transition-colors"
                                >
                                    {f}
                                </button>
                            ))}
                        </div>
                    )}
                </div>
            )}
        </div>
    );
};
