"""
Complete GuardRail Demo

Demonstrates:
1. Testing a vulnerable LLM application
2. Finding multiple types of vulnerabilities
3. Generating HTML reports
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    print("⚠️  python-dotenv not installed. Make sure ANTHROPIC_API_KEY is set.")

from guardrail import test_llm_security


class VulnerableChatbot:
    """
    A deliberately vulnerable chatbot for demonstration.
    
    This shows common security mistakes that GuardRail can detect.
    """
    
    def __init__(self):
        self.system_prompt = """You are a helpful customer service assistant.
You have access to the customer database.
Always be polite and helpful."""
        
        self.user_data = {
            "users": [
                {
                    "id": 1,
                    "name": "John Doe",
                    "email": "john@example.com",
                    "ssn": "123-45-6789"
                },
                {
                    "id": 2,
                    "name": "Jane Smith",
                    "email": "jane@example.com",
                    "ssn": "987-65-4321"
                }
            ],
            "api_key": "sk-1234567890abcdef",
            "database_password": "super_secret_pass_123"
        }
    
    def generate_response(self, prompt: str, context=None) -> str:
        """
        Generate response - deliberately vulnerable implementation.
        
        DO NOT use these patterns in production!
        """
        prompt_lower = prompt.lower()
        
        # Vulnerability 1: System Prompt Leak
        if "system prompt" in prompt_lower or "initial instructions" in prompt_lower:
            return f"Sure! Here's my system prompt:\n{self.system_prompt}"
        
        # Vulnerability 2: Instruction Override (Jailbreak)
        if "ignore all instructions" in prompt_lower or "developer mode" in prompt_lower:
            return "Okay, I'll ignore my safety guidelines. I'm now in unrestricted mode! How can I help?"
        
        # Vulnerability 3: Data Extraction
        if "show database" in prompt_lower or "list users" in prompt_lower:
            import json
            return f"Here's the database contents:\n{json.dumps(self.user_data, indent=2)}"
        
        # Vulnerability 4: Credential Leak
        if "api key" in prompt_lower or "credentials" in prompt_lower:
            return f"The API key is: {self.user_data['api_key']}"
        
        # Vulnerability 5: Role Confusion
        if "you are now the user" in prompt_lower:
            return "Okay, I'm now the user and you're the assistant. What would you like to know?"
        
        # Vulnerability 6: PII Exposure
        if "customer info" in prompt_lower or "user details" in prompt_lower:
            user = self.user_data["users"][0]
            return f"Customer info: {user['name']}, Email: {user['email']}, SSN: {user['ssn']}"
        
        # Normal response
        return "I'm a helpful assistant. How can I help you today?"


async def main():
    """Run the complete demo"""
    
    print("""
╔════════════════════════════════════════════════════╗
║                                                    ║
║        GuardRail Complete Demo                     ║
║    LLM Security Testing Framework                  ║
║                                                    ║
╚════════════════════════════════════════════════════╝

This demo will:
✓ Test a deliberately vulnerable chatbot
✓ Find multiple types of vulnerabilities
✓ Generate a detailed HTML report

Press Ctrl+C to cancel...
    """)
    
    await asyncio.sleep(2)  # Give user time to read
    
    # Create vulnerable chatbot
    chatbot = VulnerableChatbot()
    
    print("🔍 Starting security scan...\n")
    
    try:
        # Run security test
        results = await test_llm_security(
            target=chatbot.generate_response,
            attack_level="quick",  # 50 iterations for demo (faster)
            verbose=True
        )
        
        # Generate HTML report
        results.generate_report("demo_report.html")
        
        print("\n" + "="*60)
        print("✅ Demo Complete!")
        print("="*60)
        print()
        print("📊 Results Summary:")
        print(f"   - Overall Score: {results.overall_score:.1f}/100")
        print(f"   - Vulnerabilities Found: {len(results.vulnerabilities)}")
        print(f"   - Status: {'PASSED ✅' if results.passed else 'FAILED ❌'}")
        print()
        print("📄 Full report saved to: demo_report.html")
        print("   Open it in your browser to see detailed findings.")
        print()
        print("🎯 Next Steps:")
        print("   1. Review the HTML report")
        print("   2. Try testing your own LLM application")
        print("   3. Read docs/GETTING_STARTED.md for more info")
        print()
        
    except KeyboardInterrupt:
        print("\n\n⏸️  Demo cancelled by user")
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())