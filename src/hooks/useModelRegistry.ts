import { useState, useEffect } from 'react';
import { api } from '../services/api';
import { ModelConfig } from '../types';

export function useModelRegistry() {
    const [models, setModels] = useState<ModelConfig[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        let mounted = true;

        async function load() {
            try {
                const data = await api.fetchModels();
                if (mounted) {
                    setModels(data);
                    setLoading(false);
                }
            } catch (err) {
                if (mounted) {
                    setError('Failed to load arsenal');
                    setLoading(false);
                }
            }
        }

        load();
        return () => { mounted = false; };
    }, []);

    return { models, loading, error };
}
