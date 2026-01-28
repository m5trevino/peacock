import React, { useState, useEffect, useRef } from 'react';

interface LogEntry {
    id: string;
    text: string;
    timestamp: number;
}

interface BackgroundTerminalProps {
    logs: LogEntry[];
    isFocused: boolean;
}

const TypewriterLine: React.FC<{ text: string }> = ({ text }) => {
    const [displayText, setDisplayText] = useState('');
    const [isComplete, setIsComplete] = useState(false);

    useEffect(() => {
        let currentText = '';
        let index = 0;
        const interval = setInterval(() => {
            if (index < text.length) {
                currentText += text[index];
                setDisplayText(currentText);
                index++;
            } else {
                setIsComplete(true);
                clearInterval(interval);
            }
        }, Math.random() * 15 + 5); // 5ms - 20ms variable speed

        return () => clearInterval(interval);
    }, [text]);

    return (
        <div className="terminal-line">
            {displayText}
            {!isComplete && <span className="animate-pulse">█</span>}
        </div>
    );
};

export const BackgroundTerminal: React.FC<BackgroundTerminalProps> = ({ logs, isFocused }) => {
    const scrollRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (scrollRef.current) {
            scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
        }
    }, [logs, isFocused]); // Re-scroll whenever logs update OR we focus

    return (
        <div
            className={`fixed inset-0 overflow-hidden pointer-events-none transition-all duration-700 ghost-jitter
                ${isFocused ? 'z-[50] opacity-90 bg-void/95 pointer-events-auto cursor-zoom-out' : 'z-[-10] opacity-[0.15]'}
            `}
        >
            {/* CRT OVERLAY */}
            <div className="absolute inset-0 bg-void pointer-events-none opacity-[0.03] crt-overlay" />

            <div
                ref={scrollRef}
                className="w-full h-full p-10 overflow-y-auto custom-scrollbar flex flex-col gap-1"
            >
                {logs.map((log) => (
                    <TypewriterLine key={log.id} text={log.text} />
                ))}
            </div>
        </div>
    );
};
