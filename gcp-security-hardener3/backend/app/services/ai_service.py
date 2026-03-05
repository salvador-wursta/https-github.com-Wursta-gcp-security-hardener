import logging
import os
from google import genai
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

class AIService:
    """Service for interacting with Google Vertex AI (Gemini) via google-genai SDK"""
    
    def __init__(self, project_id: Optional[str] = None, location: str = "us-central1"):
        """
        Initialize Vertex AI Client.
        Uses Application Default Credentials (ADC) by omitting api_key.
        """
        try:
            # google-genai SDK handles Vertex AI when vertexai=True is passed
            # It auto-discovers ADC.
            self.client = genai.Client(
                vertexai=True,
                project=project_id or os.getenv("GOOGLE_CLOUD_PROJECT"),
                location=location
            )
            self.model_id = "gemini-1.5-flash"
            logger.info(f"Vertex AI Client initialized in {location} using ADC.")
        except Exception as e:
            logger.error(f"Failed to initialize Vertex AI Client: {str(e)}")
            self.client = None

    def generate_analysis(self, prompt: str) -> Optional[str]:
        """Generate content without using an API key (SaaS mode)"""
        if not self.client:
            logger.error("AI Client not initialized.")
            return None
            
        try:
            response = self.client.models.generate_content(
                model=self.model_id,
                contents=prompt
            )
            return response.text
        except Exception as e:
            logger.error(f"Vertex AI (google-genai) Generation failed: {str(e)}")
            return None

    def analyze_security_findings(self, findings: List[Dict[str, Any]]) -> Optional[str]:
        """Specific helper for security review context"""
        if not findings:
            return "No findings to analyze."
            
        prompt = f"Review the following GCP security findings and provide a strategic summary:\n{findings}"
        return self.generate_analysis(prompt)

    def generate_security_report(self, scans: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Generate comprehensive security report content using Vertex AI.
        Identity-based, no keys required.
        """
        if not self.client:
            return None

        import json
        
        # Aggregate context for prompt
        total_risks = 0
        critical_risks = 0
        high_risks = 0
        distinct_findings = []
        
        for scan in scans:
            risks = scan.get("risks", [])
            total_risks += len(risks)
            for r in risks:
                level = str(r.get("risk_level", "")).lower()
                if level == "critical": critical_risks += 1
                if level == "high": high_risks += 1
                
                if len(distinct_findings) < 50:
                    distinct_findings.append(f"[{level.upper()}] {r.get('title')}: {r.get('description')}")

        prompt = f"""
        Senior Cloud Security Architect Assessment.
        
        Projects: {len(scans)}
        Total Risks: {total_risks} (Critical: {critical_risks}, High: {high_risks})
        
        Findings Sample:
        {chr(10).join(distinct_findings[:30])}
        
        Task: 
        1. Write a Strategic Executive Assessment (3 paragraphs) synthesizing business risk.
        2. Provide 4-6 Strategic Recommendations (3-4 sentences each) with mitigation and business value.
        3. For each finding, provide detailed technical remediation.
        
        Format: strictly JSON.
        {{
            "executive_summary": "...",
            "recommendations": [{"title": "...", "description": "...", "priority": "..."}],
            "finding_enrichments": {{"Finding Title": "Detailed technical advice..."}}
        }}
        """
        
        try:
            response_text = self.generate_analysis(prompt + "\n\nReturn ONLY raw JSON.")
            if not response_text:
                return None
            
            # Cleanup JSON markers
            clean_json = response_text.replace("```json", "").replace("```", "").strip()
            return json.loads(clean_json)
        except Exception as e:
            logger.error(f"SaaS AI Report Generation failed: {e}")
            return None

    def chat(self, message: str, conversation_history: Optional[List[Dict[str, str]]] = None, 
             context: Optional[str] = None, scan_results: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Send a chat message to Vertex AI"""
        if not self.client:
            return {'response': None, 'error': 'Vertex AI Service not initialized.'}
        
        try:
            # Build prompt with context
            system_prompt = self._get_system_prompt(context)
            
            if scan_results:
                system_prompt += f"\n\nCurrent GCP Security Scan Results:\n{self._format_scan_results(scan_results)}"
                system_prompt += "\n\nAnalyze these results and provide specific security recommendations."
            
            full_prompt = system_prompt + "\n\nUser: " + message + "\n\nAssistant:"
            
            if conversation_history:
                history_text = "\n".join([f"{msg['role'].title()}: {msg['content']}" for msg in conversation_history[-10:]])
                full_prompt = system_prompt + "\n\nConversation History:\n" + history_text + "\n\nUser: " + message + "\n\nAssistant:"
            
            response_text = self.generate_analysis(full_prompt)
            return {'response': response_text, 'error': None}
        except Exception as e:
            logger.error(f"SaaS Chat failure: {e}")
            return {'response': None, 'error': str(e)}

    def analyze_scan_results(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze security scan results using identity-based AI"""
        if not self.client:
            return {'analysis': None, 'error': 'Vertex AI Service not initialized.'}
            
        prompt = f"""Analyze these GCP security scan results:
1. Executive Summary
2. Critical Issues
3. Specific Recommendations
4. Priority Order

Scan Results:
{self._format_scan_results(scan_results)}
"""
        response_text = self.generate_analysis(prompt)
        return {'analysis': response_text, 'error': None}

    def _get_system_prompt(self, context: Optional[str] = None) -> str:
        """Standard System Prompt"""
        base = "You are an expert AI assistant for the GCP Security Hardener. "
        if context == 'scan_results':
            return base + "Focus on security recommendations and risk mitigation."
        elif context == 'coding':
            return base + "Focus on code quality, best practices, and debugging."
        return base

    def _format_scan_results(self, scan_results: Dict[str, Any]) -> str:
        """Format scan results for prompt context"""
        formatted = f"Project: {scan_results.get('project_id', 'Unknown')}\n"
        risks = scan_results.get('risks', [])
        formatted += f"Security Risks ({len(risks)}):\n"
        for i, risk in enumerate(risks[:10], 1):
            formatted += f"{i}. [{risk.get('risk_level', 'unknown').upper()}] {risk.get('title')}\n"
        return formatted
