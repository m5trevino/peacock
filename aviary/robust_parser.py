
#!/usr/bin/env python3
"""
🦚 PEACOCK ROBUST PARSER - No More Parsing Failures
Handles all the fucked up ways LLMs return data
"""

import json
import re
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from enum import Enum

class ParseMethod(Enum):
    DIRECT_JSON = "direct_json"
    CODE_BLOCK = "code_block" 
    REGEX_EXTRACTION = "regex_extraction"
    FALLBACK_RECOVERY = "fallback_recovery"

@dataclass
class ParseResult:
    success: bool
    data: Dict[str, Any]
    method: ParseMethod
    confidence: float
    raw_response: str
    errors: List[str] = None

class RobustParser:
    """The parser that don't fuck around"""
    
    def __init__(self):
        self.success_count = 0
        self.failure_count = 0
        
    def parse(self, raw_response: str, command_type: str = "unknown") -> ParseResult:
        """Parse LLM response with multiple fallback strategies"""
        
        errors = []
        
        # STRATEGY 1: Try direct JSON parsing
        try:
            result = self._parse_direct_json(raw_response)
            if result.success:
                self.success_count += 1
                return result
            errors.extend(result.errors or [])
        except Exception as e:
            errors.append(f"Direct JSON failed: {str(e)}")
        
        # STRATEGY 2: Extract from code blocks
        try:
            result = self._parse_code_blocks(raw_response)
            if result.success:
                self.success_count += 1
                return result
            errors.extend(result.errors or [])
        except Exception as e:
            errors.append(f"Code block extraction failed: {str(e)}")
        
        # STRATEGY 3: Regex-based extraction
        try:
            result = self._parse_with_regex(raw_response, command_type)
            if result.success:
                self.success_count += 1
                return result
            errors.extend(result.errors or [])

        except Exception as e:
            errors.append(f"Regex extraction failed: {str(e)}")
        
        # STRATEGY 4: Last resort - structured fallback
        try:
            result = self._fallback_recovery(raw_response, command_type)
            self.failure_count += 1
            return result
        except Exception as e:
            errors.append(f"Fallback recovery failed: {str(e)}")
            
        # Complete failure
        self.failure_count += 1
        return ParseResult(
            success=False,
            data={},
            method=ParseMethod.FALLBACK_RECOVERY,
            confidence=0.0,
            raw_response=raw_response,
            errors=errors
        )
    
    def _parse_direct_json(self, response: str) -> ParseResult:
        """Try to parse the whole response as JSON"""
        cleaned = response.strip()
        
        try:
            data = json.loads(cleaned)
            return ParseResult(
                success=True,
                data=data,
                method=ParseMethod.DIRECT_JSON,
                confidence=1.0,
                raw_response=response
            )
        except json.JSONDecodeError as e:
            return ParseResult(
                success=False,
                data={},
                method=ParseMethod.DIRECT_JSON,
                confidence=0.0,
                raw_response=response,
                errors=[f"JSON decode error: {str(e)}"]
            )
    
    def _parse_code_blocks(self, response: str) -> ParseResult:
        """Extract JSON from markdown code blocks"""
        # Pattern for ```json or ``` code blocks
        patterns = [
            r"```json\s*\n(.*?)\n```",
            r"```\s*\n(.*?)\n```",
            r"```json\s*(.*?)```",
            r"```\s*(.*?)```"
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, response, re.DOTALL)
            for match in matches:
                cleaned_match = match.strip()
                try:
                    data = json.loads(cleaned_match)
                    return ParseResult(
                        success=True,
                        data=data,
                        method=ParseMethod.CODE_BLOCK,
                        confidence=0.9,

                        raw_response=response
                    )
                except json.JSONDecodeError:
                    continue
        
        return ParseResult(
            success=False,
            data={},
            method=ParseMethod.CODE_BLOCK,
            confidence=0.0,
            raw_response=response,
            errors=["No valid JSON found in code blocks"]
        )
    
    def _parse_with_regex(self, response: str, command_type: str) -> ParseResult:
        """Extract structured data using regex patterns"""
        
        data = {"command_type": command_type, "parsed_via": "regex"}
        
        # First try to find any confidence scores
        confidence_pattern = r"(?:confidence|score)\s*:?\s*(\d+)"
        confidence_matches = re.findall(confidence_pattern, response, re.IGNORECASE)
        if confidence_matches:
            data["confidence_score"] = int(confidence_matches[0])
        
        # Look for list patterns like ["item1", "item2"]
        list_pattern = r"\[\s*([\"'].*?[\"'])\s*\]"
        list_matches = re.findall(list_pattern, response, re.DOTALL)
        
        # Look for key findings, issues, recommendations
        findings_pattern = r"(?:findings?|issues?|problems?)\s*:?\s*\[?\s*([^\]\n]+)"
        findings_matches = re.findall(findings_pattern, response, re.IGNORECASE)
        if findings_matches:
            # Split by comma and clean up
            items = [item.strip().strip("\"'") for item in findings_matches[0].split(",") if item.strip()]
            data["key_findings"] = items
        
        # Look for recommendations
        rec_pattern = r"(?:recommendations?|suggestions?)\s*:?\s*([^\n]+)"
        rec_matches = re.findall(rec_pattern, response, re.IGNORECASE)
        if rec_matches:
            data["recommendations"] = [rec_matches[0].strip()]
        
        # Look for objectives or goals
        obj_pattern = r"(?:objective|goal|target)\s*:?\s*[\"']?(.*?)[\"']?(?:\n|$)"
        obj_matches = re.findall(obj_pattern, response, re.IGNORECASE)
        if obj_matches:
            data["core_objective"] = obj_matches[0].strip()
        
        found_data = len(data) > 2  # More than just command_type and parsed_via
        confidence = 0.7 if found_data else 0.1
        
        return ParseResult(
            success=found_data,
            data=data,
            method=ParseMethod.REGEX_EXTRACTION,
            confidence=confidence,
            raw_response=response
        )
    
    def _fallback_recovery(self, response: str, command_type: str) -> ParseResult:
        """Last resort - extract whatever we can"""
        
        data = {
            "command_type": command_type,
            "raw_content": response,

            "extraction_method": "fallback",
            "success": False,
            "message": "Parsing failed, raw content preserved"
        }
        
        # Try to find any JSON-like structures
        json_pattern = r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}'
        json_matches = re.findall(json_pattern, response)
        
        if json_matches:
            data["potential_json"] = json_matches
            # Try to parse the first potential JSON
            for potential in json_matches:
                try:
                    parsed = json.loads(potential)
                    data["extracted_json"] = parsed
                    break
                except:
                    continue
        
        # Extract any confidence scores mentioned
        confidence_pattern = r'(?:confidence|score):\s*(\d+)'
        confidence_matches = re.findall(confidence_pattern, response, re.IGNORECASE)
        if confidence_matches:
            data["confidence_score"] = int(confidence_matches[0])
        
        return ParseResult(
            success=False,  # Fallback is never "successful"
            data=data,
            method=ParseMethod.FALLBACK_RECOVERY,
            confidence=0.2,
            raw_response=response
        )
    
    def get_stats(self) -> Dict[str, Any]:
        """Get parsing statistics"""
        total = self.success_count + self.failure_count
        success_rate = (self.success_count / total * 100) if total > 0 else 0
        
        return {
            "total_parses": total,
            "successes": self.success_count,
            "failures": self.failure_count,
            "success_rate": f"{success_rate:.1f}%"
        }

# Test the parser
if __name__ == "__main__":
    parser = RobustParser()
    
    # Test cases
    test_responses = [
        '{"command_type": "spark", "confidence_score": 8, "core_objective": "Build snake game"}',
        '''```json
        {"command_type": "analyze", "key_findings": ["No error handling", "Magic numbers"]}
        ```''',
        'The confidence score is 7 and the main issues are: authentication problems, database errors.',
        'Complete garbage response with no structure at all'
    ]
    
    for i, response in enumerate(test_responses, 1):
        result = parser.parse(response, "test")
        print(f"\nTest {i}: {result.method.value} - Success: {result.success}")
        print(f"Data: {result.data}")
        print(f"Confidence: {result.confidence}")
    
    print(f"\nStats: {parser.get_stats()}")

