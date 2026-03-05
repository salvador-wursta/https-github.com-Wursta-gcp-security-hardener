"""
Pydantic models for Gemini chat requests and responses
"""
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class ChatMessage(BaseModel):
    """Individual chat message"""
    role: str = Field(..., description="Message role: 'user' or 'assistant'")
    content: str = Field(..., description="Message content")


class ChatRequest(BaseModel):
    """Request to chat with Gemini"""
    message: str = Field(..., description="User's message")
    conversation_history: Optional[List[ChatMessage]] = Field(None, description="Previous conversation messages")
    context: Optional[str] = Field(None, description="Context: 'scan_results', 'coding', or None")
    scan_results: Optional[Dict[str, Any]] = Field(None, description="Optional scan results for context")


class ChatResponse(BaseModel):
    """Response from Gemini chat"""
    response: Optional[str] = Field(None, description="AI assistant's response")
    error: Optional[str] = Field(None, description="Error message if request failed")


class AnalyzeScanRequest(BaseModel):
    """Request to analyze scan results"""
    scan_results: Dict[str, Any] = Field(..., description="Security scan results to analyze")


class AnalyzeScanResponse(BaseModel):
    """Response from scan analysis"""
    analysis: Optional[str] = Field(None, description="AI analysis of scan results")
    error: Optional[str] = Field(None, description="Error message if analysis failed")

