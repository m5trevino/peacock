import React, { useEffect, useState } from 'react';

interface MatrixTextProps {
    text: string;
    delay?: number;
    className?: string;
    onComplete?: () => void;
}

const GLYPHS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()_+";

export const MatrixText: React.FC<MatrixTextProps> = ({
    text,
    delay = 0,
    className = "",
    onComplete
}) => {
    const [displayText, setDisplayText] = useState("");
    const [isComplete, setIsComplete] = useState(false);

    useEffect(() => {
        let iteration = 0;
        let interval: any = null;

        const startEffect = () => {
            // High-Speed Lockdown: Strings over 50 chars lock in near-instantly.
            const step = text.length > 50 ? text.length / 5 : Math.max(1, text.length / 20);

            interval = setInterval(() => {
                setDisplayText(prev =>
                    text.split("")
                        .map((char, index) => {
                            if (index < iteration) {
                                return text[index];
                            }
                            return GLYPHS[Math.floor(Math.random() * GLYPHS.length)];
                        })
                        .join("")
                );

                if (iteration >= text.length) {
                    clearInterval(interval);
                    setIsComplete(true);
                    onComplete?.();
                }

                iteration += step;
            }, 10); // Ultra-fast interval (10ms)
        };

        const timeout = setTimeout(startEffect, delay);

        return () => {
            clearInterval(interval);
            clearTimeout(timeout);
        };
    }, [text, delay, onComplete]);

    return (
        <span className={`${className} ${isComplete ? 'descramble-lock' : ''}`}>
            {displayText || text.split("").map(() => " ").join("")}
        </span>
    );
};
