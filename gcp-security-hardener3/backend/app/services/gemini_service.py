"""
Gemini AI Assistant Service
Provides coding assistance and GCP security analysis
"""
import os
import logging
from typing import List, Dict, Any, Optional

try:
    from google import genai
except ImportError:
    genai = None

logger = logging.getLogger(__name__)


class GeminiService:
    """Service for interacting with Google Gemini AI"""
    
    def __init__(self):
        self.api_key = os.getenv('GEMINI_API_KEY')
        if not self.api_key:
            logger.warning("GEMINI_API_KEY not set - Gemini features will be disabled")
            self.client = None
        elif genai is None:
            logger.warning("google-genai package not installed - Gemini features will be disabled")
            logger.warning("Install with: pip install google-genai")
            self.client = None
        else:
            try:
                self.client = genai.Client(api_key=self.api_key)
                logger.info("Gemini service initialized")
            except Exception as e:
                logger.error(f"Failed to initialize Gemini service: {str(e)}")
                self.client = None
    
    def is_available(self) -> bool:
        """Check if Gemini is available"""
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
        Send a chat message to Gemini
        
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
                'error': 'Gemini API key not configured. Please set GEMINI_API_KEY environment variable.'
            }
        
        try:
            # Build the prompt with context
            system_prompt = self._get_system_prompt(context)
            
            # Add scan results context if provided
            if scan_results:
                system_prompt += f"\n\nCurrent GCP Security Scan Results:\n{self._format_scan_results(scan_results)}"
                system_prompt += "\n\nAnalyze these results and provide specific security recommendations."
            
            # Build conversation
            full_prompt = system_prompt + "\n\nUser: " + message + "\n\nAssistant:"
            
            # Add conversation history if provided
            if conversation_history:
                history_text = "\n".join([
                    f"{msg['role'].title()}: {msg['content']}"
                    for msg in conversation_history[-10:]  # Last 10 messages
                ])
                full_prompt = system_prompt + "\n\nConversation History:\n" + history_text + "\n\nUser: " + message + "\n\nAssistant:"
            
            # Generate response
            logger.info(f"Generating Gemini response for context: {context}")
            response = self.client.models.generate_content(
                model='gemini-2.0-flash',
                contents=full_prompt
            )
            
            return {
                'response': response.text,
                'error': None
            }
        
        except Exception as e:
            logger.error(f"Error generating Gemini response: {str(e)}")
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
                'error': 'Gemini API key not configured.'
            }
        
        try:
            prompt = f"""Analyze these GCP security scan results and provide:

1. **Executive Summary**: Brief overview of the security posture
2. **Critical Issues**: List the most critical security risks that need immediate attention
3. **Recommendations**: Specific, actionable steps to remediate each risk
4. **Priority Order**: Suggested order for addressing issues
5. **Best Practices**: General GCP security best practices relevant to these findings

Scan Results:
{self._format_scan_results(scan_results)}

Provide a clear, actionable analysis that a non-technical user can understand."""
            
            response = self.client.models.generate_content(
                model='gemini-2.0-flash',
                contents=prompt
            )
            
            return {
                'analysis': response.text,
                'error': None
            }
        
        except Exception as e:
            logger.error(f"Error analyzing scan results: {str(e)}")
            return {
                'analysis': None,
                'error': f"Failed to analyze scan results: {str(e)}"
            }
    
    def generate_security_report(self, scans: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate comprehensive security report content using Gemini.
        Returns Executive Summary and Strategic Recommendations in JSON format.
        """
        if not self.is_available():
            return None

        try:
            # 1. Aggregate context for prompt
            total_risks = 0
            critical_risks = 0
            high_risks = 0
            distinct_findings = []
            
            for scan in scans:
                risks = scan.get("risks", [])
                total_risks += len(risks)
                for r in risks:
                    level = r.get("risk_level", "").lower()
                    if level == "critical": critical_risks += 1
                    if level == "high": high_risks += 1
                    
                    # Capture unique findings for context (limit to avoid token overflow)
                    if len(distinct_findings) < 50:
                        distinct_findings.append(f"[{level.upper()}] {r.get('title')}: {r.get('description')}")

            prompt = f"""
            You are a Senior Cloud Security Architect. Review these GCP scan results and generate a security assessment report.
            
            **Scan Context:**
            - Projects Scanned: {len(scans)}
            - Total Risks: {total_risks}
            - Critical Risks: {critical_risks}
            - High Risks: {high_risks}
            
            **Key Findings (Sample):**
            {chr(10).join(distinct_findings[:30])}
            
            **Instructions:**
            1. Write a detailed **Strategic Executive Assessment** (minimum 3 paragraphs). 
               - **Synthesize** the Key Findings into a cohesive narrative about business risk.
               - Do NOT just list stats (e.g. "There are 5 risks"). Explain the *implications* and *root causes*.
               - Explicitly reference the most critical risks found (by name) and explain why they are dangerous in this specific context.
               - Use professional, executive-level language suitable for a CISO.

            2. Provide 4-6 **Strategic Recommendations**. 
               - Each recommendation description MUST be at least 3-4 sentences long.
               - Explicitly describe the mitigation strategy and the business value.
            3. **VITAL**: For each "Key Finding", provide a DETAILED, TECHNICAL remediation recommendation.
               - The recommendation MUST be at least 2-3 sentences long.
               - Include specific `gcloud` commands, Terraform resource changes, or IAM role names to use.
               - Explain NOT just "what" to do, but "how" to do it concretely.
            
            **Output Format (JSON):**
            {{
                "executive_summary": "...",
                "recommendations": [
                    {{
                        "title": "...",
                        "description": "...",
                        "priority": "Critical|High|Medium"
                    }}
                ],
                "finding_enrichments": {{
                    "[Original Finding Title]": "Specific AI Recommendation...",
                    "[Another Title]": "Specific AI Recommendation..."
                }}
            }}
            
            Return ONLY validated JSON.
            """
            
            response = self.client.models.generate_content(
                model='gemini-2.0-flash', # Use flash model for speed/cost if available, or fall back to known model
                contents=prompt,
                config={'response_mime_type': 'application/json'} # Force JSON
            )
            
            import json
            return json.loads(response.text)

        except Exception as e:
            logger.error(f"Gemini report generation failed: {str(e)}")
            # Fallback to older model if 2.0-flash not avail
            try:
                 logger.info("Retrying with gemini-1.5-flash...")
                 response = self.client.models.generate_content(
                    model='gemini-1.5-flash',
                    contents=prompt + "\n\nResponse must be valid JSON.",
                 )
                 # naive json cleanup if needed
                 text = response.text.replace("```json", "").replace("```", "").strip()
                 return json.loads(text)
            except Exception as e2:
                logger.error(f"Retry failed: {str(e2)}")
                return None

    def _format_scan_results(self, scan_results: Dict[str, Any]) -> str:
        """Format scan results for Gemini prompt"""
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
            affected = risk.get('affected_resources') or []
            if affected:
                formatted += f"   Affected: {', '.join(affected[:5])}\n"
            formatted += "\n"
        
        if len(risks) > 10:
            formatted += f"... and {len(risks) - 10} more risks\n"
        
        return formatted

