"""
Claude AI Assistant API endpoints
"""
from fastapi import APIRouter, HTTPException, Depends
from app.models.claude_models import ChatRequest, ChatResponse, AnalyzeScanRequest, AnalyzeScanResponse
from app.services.claude_service import ClaudeService
from app.api.dependencies import verify_token
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/claude", tags=["claude"])

# Initialize Claude service
claude_service = ClaudeService()


@router.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest, user: dict = Depends(verify_token)):
    """
    Chat with Claude AI assistant (requires authentication)
    
    Supports:
    - General coding questions about the application
    - GCP security questions
    - Analysis of scan results (when scan_results provided)
    """
    try:
        logger.info(f"Claude chat request from user {user.get('email', 'unknown')}: context={request.context}, message_length={len(request.message)}")
        
        # Convert conversation history format if provided
        conversation_history = None
        if request.conversation_history:
            conversation_history = [
                {"role": msg.role, "content": msg.content}
                for msg in request.conversation_history
            ]
        
        result = claude_service.chat(
            message=request.message,
            conversation_history=conversation_history,
            context=request.context,
            scan_results=request.scan_results
        )
        
        if result['error']:
            raise HTTPException(status_code=500, detail=result['error'])
        
        return ChatResponse(
            response=result['response'],
            error=None
        )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in Claude chat endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Chat failed: {str(e)}")


@router.post("/analyze-scan", response_model=AnalyzeScanResponse)
async def analyze_scan(request: AnalyzeScanRequest, user: dict = Depends(verify_token)):
    """
    Analyze security scan results using Claude AI (requires authentication)
    
    Provides:
    - Executive summary
    - Critical issues identification
    - Prioritized recommendations
    - Best practices
    """
    try:
        logger.info(f"Claude analyze scan request from user {user.get('email', 'unknown')} for project: {request.scan_results.get('project_id', 'unknown')}")
        
        result = claude_service.analyze_scan_results(request.scan_results)
        
        if result['error']:
            raise HTTPException(status_code=500, detail=result['error'])
        
        return AnalyzeScanResponse(
            analysis=result['analysis'],
            error=None
        )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in Claude analyze-scan endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.get("/health")
async def health():
    """Check if Claude service is available"""
    return {
        "available": claude_service.is_available(),
        "status": "ok" if claude_service.is_available() else "unavailable - CLAUDE_API_KEY or ANTHROPIC_API_KEY not set"
    }
