"""
Peacock Aviary - Modular AI Development Pipeline
Each bird specializes in one domain for optimal results
"""

from .spark import SparkAnalyst
from .falcon import FalconArchitect  
from .eagle import EagleImplementer
from .hawk import HawkQASpecialist
from .homing import HomingOrchestrator
from .return_homing import ReturnHomingProcessor

__version__ = "2.0.0"
__author__ = "Peacock Development Team"

# Export main classes
__all__ = [
    'SparkAnalyst',
    'FalconArchitect', 
    'EagleImplementer',
    'HawkQASpecialist',
    'HomingOrchestrator',
    'ReturnHomingProcessor'
]

# Bird factory functions
def create_spark_analyst():
    """Factory function for SPARK requirements analyst"""
    return SparkAnalyst()

def create_falcon_architect():
    """Factory function for FALCON system architect"""
    return FalconArchitect()

def create_eagle_implementer():
    """Factory function for EAGLE code implementer"""
    return EagleImplementer()

def create_hawk_qa_specialist():
    """Factory function for HAWK QA specialist"""
    return HawkQASpecialist()

def create_homing_orchestrator():
    """Factory function for HOMING pipeline orchestrator"""
    return HomingOrchestrator()

def create_return_homing_processor():
    """Factory function for RETURN-HOMING response processor"""
    return ReturnHomingProcessor()

# Pipeline configuration
OPTIMAL_MODEL_ASSIGNMENTS = {
    "spark_analysis": "llama3-8b-8192",        # Speed for requirements
    "falcon_architecture": "gemma2-9b-it",     # Structure champion  
    "eagle_implementation": "llama-3.1-8b-instant", # Code generation beast
    "hawk_qa": "gemma2-9b-it",                  # QA structure
    "code_analysis": "llama-3.1-8b-instant"    # Code review king
}

PIPELINE_STAGES = [
    "spark_analysis",
    "falcon_architecture", 
    "eagle_implementation",
    "hawk_qa"
]