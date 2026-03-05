"""
Gemini AI Assistant API endpoints
"""
from fastapi import APIRouter, HTTPException, Depends
from app.models.gemini_models import ChatRequest, ChatResponse, AnalyzeScanRequest, AnalyzeScanResponse
from app.services.ai_service import AIService
from app.api.dependencies import verify_token
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/gemini", tags=["gemini"])

# Initialize identity-based AI service
ai_service = AIService()


@router.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest, user: dict = Depends(verify_token)):
    """
    Chat with Gemini AI assistant (requires authentication)
    
    Supports:
    - General coding questions about the application
    - GCP security questions
    - Analysis of scan results (when scan_results provided)
    """
    try:
        logger.info(f"Chat request from user {user.get('email', 'unknown')}: context={request.context}, message_length={len(request.message)}")
        
        # Convert conversation history format if provided
        conversation_history = None
        if request.conversation_history:
            conversation_history = [
                {"role": msg.role, "content": msg.content}
                for msg in request.conversation_history
            ]
        
        result = ai_service.chat(
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
        logger.error(f"Error in chat endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Chat failed: {str(e)}")


@router.post("/analyze-scan", response_model=AnalyzeScanResponse)
async def analyze_scan(request: AnalyzeScanRequest, user: dict = Depends(verify_token)):
    """
    Analyze security scan results using Gemini AI (requires authentication)
    
    Provides:
    - Executive summary
    - Critical issues identification
    - Prioritized recommendations
    - Best practices
    """
    try:
        logger.info(f"Analyze scan request from user {user.get('email', 'unknown')} for project: {request.scan_results.get('project_id', 'unknown')}")
        
        result = ai_service.analyze_scan_results(request.scan_results)
        
        if result['error']:
            raise HTTPException(status_code=500, detail=result['error'])
        
        return AnalyzeScanResponse(
            analysis=result['analysis'],
            error=None
        )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in analyze-scan endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.get("/health")
async def health():
    """Check if Gemini service is available"""
    return {
        "available": ai_service.model is not None,
        "status": "ok" if ai_service.model else "unavailable - Vertex AI initialization failed"
    }

