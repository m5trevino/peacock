import React from 'react';
import { SystemDiagnostics } from '../SystemDiagnostics';

interface CommandHUDProps {
    onReset: () => void;
    onSettings: () => void;
}

export const CommandHUD: React.FC<CommandHUDProps> = ({ onReset, onSettings }) => {
    return (
        <div className="flex items-center justify-between p-4 border-b border-gray-800 bg-[#050505] z-50">
            <div className="flex items-center space-x-4">
                <h1 className="text-xl font-bold text-[#00FF41] font-mono tracking-tighter">
                    PEACOCK<span className="text-gray-600">_V21</span>
                </h1>
                <SystemDiagnostics />
            </div>

            <div className="flex items-center space-x-2">
                <button
                    onClick={onReset}
                    className="px-3 py-1 text-xs font-mono text-gray-400 hover:text-red-400 border border-transparent hover:border-red-900 transition-colors"
                >
                    [SYSTEM FLUSH]
                </button>
                <button
                    onClick={onSettings}
                    className="px-3 py-1 text-xs font-mono text-[#00FF41] border border-[#00FF41]/30 hover:bg-[#00FF41]/10 transition-colors"
                >
                    [SETTINGS]
                </button>
            </div>
        </div>
    );
};
