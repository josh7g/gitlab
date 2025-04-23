from typing import Dict, Union, Tuple

def calculate_overall_progress(stage: str, stage_progress: float) -> int:

    # Comprehensive stage weights covering different scanning stages
    STAGE_WEIGHTS: Dict[str, Dict[str, Union[int, Tuple[int, int]]]] = {
        'initializing': {'range': (0, 10)},    
        'cloning': {'range': (10, 20)},         
        'analyzing': {'range': (20, 80)},       
        'processing': {'range': (80, 95)},    
        'reranking': {'range': (95, 98)},      
        'completed': {'range': (100, 100)},    
        'error': {'range': (0, 0)}              
    }

    # Handle special cases
    if stage not in STAGE_WEIGHTS:
        return 0
        
    if stage == 'error':
        return 0
        
    if stage == 'completed':
        return 100
    
    # Get the range for the current stage
    stage_start, stage_end = STAGE_WEIGHTS[stage]['range']
    
    # Ensure stage progress is between 0 and 100
    normalized_progress = max(0, min(100, stage_progress))
    
    # Calculate progress within the stage's range
    stage_range = stage_end - stage_start
    progress_in_stage = (normalized_progress / 100.0) * stage_range
    
    # Add the progress to the stage's start point
    overall_progress = stage_start + progress_in_stage
    
    # Ensure the progress is within bounds and round to the nearest whole number
    return round(min(max(overall_progress, stage_start), stage_end))
