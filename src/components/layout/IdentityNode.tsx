import React, { useState, useEffect } from 'react';

// Simplified Identity Node that doesn't rely on 7 images initially to avoid missing asset errors.
// It will just show a stylized text node for now, or a single placeholder.

export const IdentityNode: React.FC = () => {
    return (
        <div className="w-12 h-12 rounded-full bg-[#050505] border border-[#00FF41] flex items-center justify-center shadow-[0_0_10px_rgba(0,255,65,0.3)]">
            <span className="text-xl">🦚</span>
        </div>
    );
};
