import React, { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { LogEntry } from '../../types';

interface MatrixTerminalProps {
    logs: LogEntry[];
    casinoMode?: boolean;
}

export const MatrixTerminal: React.FC<MatrixTerminalProps> = ({ logs, casinoMode = false }) => {
    // We only show the last 20 logs to keep it performant
    const visibleLogs = logs.slice(-20);

    return (
        <div className="fixed inset-0 z-0 pointer-events-none overflow-hidden flex flex-col justify-end pb-10 pl-10 opacity-20">
            <div className={`w-1/2 flex flex-col gap-1 font-mono text-[10px] uppercase tracking-widest text-matrix/50 ${casinoMode ? 'drop-shadow-[0_0_5px_rgba(0,255,65,0.8)] animate-pulse' : ''}`}>
                {visibleLogs.map((log) => (
                    <motion.div
                        key={log.id}
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        exit={{ opacity: 0 }}
                        className={`
                            whitespace-nowrap 
                            ${log.type === 'error' ? 'text-error' : log.type === 'success' ? 'text-matrix' : 'text-white/30'}
                        `}
                    >
                        <span className="opacity-50">[{new Date(log.timestamp).toLocaleTimeString()}]</span> {log.message}
                    </motion.div>
                ))}
            </div>
            {/* Gradient Mask to fade top */}
            <div className="absolute top-0 left-0 w-full h-1/2 bg-gradient-to-b from-void to-transparent" />
        </div>
    );
};
