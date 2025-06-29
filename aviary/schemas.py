
#!/usr/bin/env python3
"""
schemas.py - Pydantic Schemas for Peacock Pipeline
Defines the data structures for robust, type-safe parsing.
"""


from pydantic import BaseModel, Field
from typing import List, Optional

class CodeFile(BaseModel):
    """Defines the structure for a single code file."""

    filename: str = Field(description="The complete filename, including extension.")
    language: str = Field(description="The programming language of the code, e.g., 'python', 'html'.")
    code: str = Field(description="The complete, raw source code for the file.")

class FinalCodeOutput(BaseModel):

    """
    Defines the expected JSON structure for the final code generation step.
    The LLM is instructed to return its output in this format.
    """
    project_name: str = Field(description="The name of the generated project.")
    files: List[CodeFile] = Field(description="A list of all code files for the project.")

