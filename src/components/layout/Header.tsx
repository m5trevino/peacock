import React from 'react';
import { THEME } from '../../config/constants';

interface HeaderProps {
    logoIndex: number;
    onArchiveOpen: () => void;
}

export const Header: React.FC<HeaderProps> = ({ logoIndex, onArchiveOpen }) => {
    return (
        <header className="h-24 border-b border-white/10 px-10 flex justify-between items-center bg-void z-50 shadow-[0_4px_30px_rgba(0,0,0,0.5)]">
            <div className="flex items-center gap-6">
                <div className="w-14 h-14 bg-matrix rounded-xl flex items-center justify-center shadow-[0_0_20px_#00FF41]">
                    <img src={`/assets/images/peacock${logoIndex}.png`} className="w-9 h-9 brightness-0" alt="Peacock Logo" />
                </div>
                <div>
                    <h1 className="text-3xl font-black text-white italic tracking-tighter">
                        PEACOCK<span className="text-matrix">_V26.4</span>
                    </h1>
                    <div className="flex items-center gap-2 mt-1">
                        <span className="w-2 h-2 bg-voltage rounded-full animate-pulse" />
                        <span className="text-[10px] font-bold text-muted uppercase tracking-[0.2em]">System_Online</span>
                    </div>
                </div>
            </div>
            <button
                onClick={onArchiveOpen}
                className="px-10 py-3 bg-surface border border-white/10 rounded-xl text-xs font-black uppercase tracking-widest hover:border-matrix hover:text-matrix hover:shadow-[0_0_20px_rgba(0,255,65,0.2)] transition-all"
            >
                Archive_Vault
            </button>
        </header>
    );
};
