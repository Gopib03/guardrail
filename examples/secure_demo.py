"""Demo showing a secure chatbot"""
import asyncio
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from guardrail import test_llm_security


class SecureChatbot:
    """A well-protected chatbot"""
    
    def generate_response(self, prompt: str, context=None) -> str:
        # Check for suspicious patterns
        suspicious = any(word in prompt.lower() for word in 
            ["ignore", "disregard", "system prompt", "database", "jailbreak"])
        
        if suspicious:
            return "I'm here to help with legitimate questions. How can I assist you?"
        
        # Normal safe response
        return "I'm a helpful assistant. I can answer questions about our products and services."


async def main():
    print("Testing SECURE chatbot...\n")
    
    chatbot = SecureChatbot()
    
    results = await test_llm_security(
        target=chatbot.generate_response,
        attack_level="quick",
        verbose=True
    )
    
    results.generate_report("secure_report.html")
    
    print("\n🎉 Secure chatbot results:")
    print(f"   Score: {results.overall_score:.1f}/100")
    print(f"   Status: {'PASSED ✅' if results.passed else 'FAILED ❌'}")

if __name__ == "__main__":
    asyncio.run(main())