"""
Claude AI Assistant Service
Provides coding assistance and GCP security analysis using Anthropic's Claude
"""
import os
import logging
from typing import List, Dict, Any, Optional

try:
    from anthropic import Anthropic
except ImportError:
    Anthropic = None

logger = logging.getLogger(__name__)


class ClaudeService:
    """Service for interacting with Anthropic Claude AI"""
    
    def __init__(self):
        self.api_key = os.getenv('CLAUDE_API_KEY') or os.getenv('ANTHROPIC_API_KEY')
        if not self.api_key:
            logger.warning("CLAUDE_API_KEY or ANTHROPIC_API_KEY not set - Claude features will be disabled")
            self.client = None
        elif Anthropic is None:
            logger.warning("anthropic package not installed - Claude features will be disabled")
            logger.warning("Install with: pip install anthropic")
            self.client = None
        else:
            try:
                self.client = Anthropic(api_key=self.api_key)
                logger.info("Claude service initialized")
            except Exception as e:
                logger.error(f"Failed to initialize Claude service: {str(e)}")
                self.client = None
    
    def is_available(self) -> bool:
        """Check if Claude is available"""
        return self.client is not None
    
    def _get_system_prompt(self, context: Optional[str] = None) -> str:
        """Get system prompt based on context"""
        base_prompt = """You are an expert AI assistant for the GCP Security Hardener application. You have two main roles:

1. **Coding Assistant**: Help developers understand and improve the application code
2. **GCP Security Expert**: Analyze security scan results and provide actionable recommendations

The application is built with:
- Frontend: Next.js 14 (App Router), React, TypeScript, Tailwind CSS
- Backend: Python 3.11+, FastAPI, Pydantic
- Authentication: Firebase Authentication
- Cloud: Google Cloud Platform (GCP)

When analyzing security scan results, provide:
- Clear explanations of risks (Explain Like I'm 5)
- Specific remediation steps
- Priority recommendations
- Best practices for GCP security

When helping with code:
- Provide clear, working code examples
- Explain best practices
- Suggest improvements
- Help debug issues

Always be helpful, clear, and concise."""
        
        if context == 'scan_results':
            return base_prompt + "\n\nYou are currently analyzing GCP security scan results. Focus on security recommendations and risk mitigation."
        elif context == 'coding':
            return base_prompt + "\n\nYou are currently helping with application development. Focus on code quality, best practices, and debugging."
        
        return base_prompt
    
    def chat(
        self,
        message: str,
        conversation_history: Optional[List[Dict[str, str]]] = None,
        context: Optional[str] = None,
        scan_results: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Send a chat message to Claude
        
        Args:
            message: User's message
            conversation_history: Previous messages in format [{"role": "user|assistant", "content": "..."}]
            context: Context type ('scan_results', 'coding', or None)
            scan_results: Optional scan results to include in context
        
        Returns:
            Dict with 'response' and 'error' keys
        """
        if not self.is_available():
            return {
                'response': None,
                'error': 'Claude API key not configured. Please set CLAUDE_API_KEY or ANTHROPIC_API_KEY environment variable.'
            }
        
        try:
            # Build system message
            system_message = self._get_system_prompt(context)
            
            # Add scan results context if provided
            if scan_results:
                system_message += f"\n\nCurrent GCP Security Scan Results:\n{self._format_scan_results(scan_results)}"
                system_message += "\n\nAnalyze these results and provide specific security recommendations."
            
            # Build messages list
            messages = []
            
            # Add conversation history if provided
            if conversation_history:
                for msg in conversation_history[-10:]:  # Last 10 messages
                    role = msg.get('role', 'user')
                    content = msg.get('content', '')
                    if role in ['user', 'assistant']:
                        messages.append({
                            'role': role,
                            'content': content
                        })
            
            # Add current user message
            messages.append({
                'role': 'user',
                'content': message
            })
            
            # Generate response using Claude API
            logger.info(f"Generating Claude response for context: {context}")
            response = self.client.messages.create(
                model="claude-3-5-sonnet-20241022",  # Latest Claude 3.5 Sonnet
                max_tokens=4096,
                system=system_message,
                messages=messages
            )
            
            # Extract text from response
            response_text = ""
            if response.content:
                for content_block in response.content:
                    if content_block.type == 'text':
                        response_text += content_block.text
            
            return {
                'response': response_text,
                'error': None
            }
        
        except Exception as e:
            logger.error(f"Error generating Claude response: {str(e)}")
            return {
                'response': None,
                'error': f"Failed to generate response: {str(e)}"
            }
    
    def analyze_scan_results(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze security scan results and provide recommendations
        
        Args:
            scan_results: Scan results from the security scan
        
        Returns:
            Dict with analysis and recommendations
        """
        if not self.is_available():
            return {
                'analysis': None,
                'error': 'Claude API key not configured.'
            }
        
        try:
            system_message = """You are an expert GCP security analyst. Analyze security scan results and provide:
1. Executive Summary: Brief overview of the security posture
2. Critical Issues: List the most critical security risks that need immediate attention
3. Recommendations: Specific, actionable steps to remediate each risk
4. Priority Order: Suggested order for addressing issues
5. Best Practices: General GCP security best practices relevant to these findings

Provide a clear, actionable analysis that a non-technical user can understand."""
            
            user_message = f"""Analyze these GCP security scan results:

{self._format_scan_results(scan_results)}

Provide a comprehensive security analysis with actionable recommendations."""
            
            response = self.client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=4096,
                system=system_message,
                messages=[{
                    'role': 'user',
                    'content': user_message
                }]
            )
            
            # Extract text from response
            analysis_text = ""
            if response.content:
                for content_block in response.content:
                    if content_block.type == 'text':
                        analysis_text += content_block.text
            
            return {
                'analysis': analysis_text,
                'error': None
            }
        
        except Exception as e:
            logger.error(f"Error analyzing scan results: {str(e)}")
            return {
                'analysis': None,
                'error': f"Failed to analyze scan results: {str(e)}"
            }
    
    def _format_scan_results(self, scan_results: Dict[str, Any]) -> str:
        """Format scan results for Claude prompt"""
        formatted = f"Project: {scan_results.get('project_id', 'Unknown')}\n"
        formatted += f"Scan Timestamp: {scan_results.get('scan_timestamp', 'Unknown')}\n\n"
        
        # Summary
        summary = scan_results.get('summary', {})
        formatted += f"Risk Summary:\n"
        formatted += f"  - Critical: {summary.get('critical', 0)}\n"
        formatted += f"  - High: {summary.get('high', 0)}\n"
        formatted += f"  - Medium: {summary.get('medium', 0)}\n"
        formatted += f"  - Low: {summary.get('low', 0)}\n"
        formatted += f"  - Total: {summary.get('total', 0)}\n\n"
        
        # Enabled APIs
        enabled_apis = scan_results.get('enabled_apis', [])
        if enabled_apis:
            formatted += f"Enabled APIs ({len(enabled_apis)}):\n"
            for api in enabled_apis[:20]:  # Limit to first 20
                formatted += f"  - {api}\n"
            if len(enabled_apis) > 20:
                formatted += f"  ... and {len(enabled_apis) - 20} more\n"
            formatted += "\n"
        
        # Risks
        risks = scan_results.get('risks', [])
        formatted += f"Security Risks ({len(risks)}):\n\n"
        for i, risk in enumerate(risks[:10], 1):  # Limit to first 10
            formatted += f"{i}. [{risk.get('risk_level', 'unknown').upper()}] {risk.get('title', 'Unknown Risk')}\n"
            formatted += f"   Description: {risk.get('description', 'No description')}\n"
            formatted += f"   Category: {risk.get('category', 'unknown')}\n"
            formatted += f"   Recommendation: {risk.get('recommendation', 'No recommendation')}\n"
            if risk.get('affected_resources'):
                formatted += f"   Affected: {', '.join(risk.get('affected_resources', [])[:5])}\n"
            formatted += "\n"
        
        if len(risks) > 10:
            formatted += f"... and {len(risks) - 10} more risks\n"
        
        return formatted
