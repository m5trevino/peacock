import { PipelineStage } from '../types';

export const THEME = {
    void: '#050505',
    surface: '#0A0B0D',
    elevated: '#121418',
    matrix: '#00FF41',
    voltage: '#FFD700',
    spark: '#0066FF',
    falcon: '#BC13FE',
    eagle: '#FF8C00',
    error: '#FF3131',
    glass: 'rgba(5, 5, 5, 0.85)',
};

export const STAGES = [
    { id: PipelineStage.SPARK, label: 'SPARK', color: THEME.spark, icon: '⚡' },
    { id: PipelineStage.FALCON, label: 'FALCON', color: THEME.falcon, icon: '🦅' },
    { id: PipelineStage.EAGLE, label: 'EAGLE', color: THEME.eagle, icon: '🦅' },
    { id: PipelineStage.OWL, label: 'OWL', color: THEME.matrix, icon: '🦉' },
    { id: PipelineStage.HAWK, label: 'HAWK', color: THEME.matrix, icon: '🦅' }
];

export const ENGINE_URL = 'http://localhost:3099/v1';

export const EAGLE_JSON_SCHEMA = {
    "type": "json_schema",
    "json_schema": {
        "name": "eagle_scaffold",
        "strict": true,
        "schema": {
            "type": "object",
            "properties": {
                "project": { "type": "string" },
                "files": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "path": { "type": "string" },
                            "skeleton": { "type": "string" },
                            "directives": { "type": "string" }
                        },
                        "required": ["path", "skeleton", "directives"],
                        "additionalProperties": false
                    }
                }
            },
            "required": ["project", "files"],
            "additionalProperties": false
        }
    }
};
