import logging
from typing import Dict, Any, List
from langchain_openai import ChatOpenAI
from langchain_community.llms import Ollama
from langchain.prompts import ChatPromptTemplate
from core.config import settings

logger = logging.getLogger(__name__)

class AIOrchestrator:
    """Orchestrates multi-agent analysis using LLMs."""
    
    def __init__(self, provider: str = "ollama"):
        self.provider = provider
        if provider == "openai":
            self.llm = ChatOpenAI(api_key=settings.openai_api_key, model="gpt-4-turbo-preview")
        else:
            self.llm = Ollama(model="llama2") # Default to local
            
    async def analyze_sample(self, 
                             static_data: Dict[str, Any], 
                             mitre_data: List[Dict[str, Any]], 
                             cti_data: Dict[str, Any]) -> str:
        """Coordinar el informe final basado en múltiples entradas."""
        
        prompt = ChatPromptTemplate.from_template("""
        Eres un experto en Malware Analysis. Analiza la siguiente información y genera un reporte técnico profesional:
        
        DATOS ESTÁTICOS: {static}
        CORRELACIÓN MITRE: {mitre}
        INTELIGENCIA CTI: {cti}
        
        Tu reporte debe incluir:
        1. Resumen ejecutivo del riesgo.
        2. Técnicas ATT&CK identificadas.
        3. Veredicto final (Limpio, Sospechoso, Malicioso).
        4. Recomendaciones de mitigación.
        """)
        
        chain = prompt | self.llm
        
        try:
            response = await chain.ainvoke({
                "static": str(static_data),
                "mitre": str(mitre_data),
                "cti": str(cti_data)
            })
            return response.content if hasattr(response, 'content') else str(response)
        except Exception as e:
            logger.error(f"AI Orchestration Error: {e}")
            return f"Error en orquestación IA: {str(e)}"

ai_orchestrator = AIOrchestrator()
