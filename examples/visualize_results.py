"""Create comparison visualization"""
import matplotlib.pyplot as plt

# Data
chatbots = ['Vulnerable\nChatbot', 'Secure\nChatbot', 'Production\nTarget']
scores = [9, 85, 95]
vulns = [13, 2, 0]

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

# Security scores
colors = ['#dc3545', '#ffc107', '#28a745']
ax1.bar(chatbots, scores, color=colors)
ax1.set_ylabel('Security Score (0-100)')
ax1.set_title('GuardRail Security Scores')
ax1.axhline(y=70, color='r', linestyle='--', label='Passing Threshold')
ax1.legend()

# Vulnerabilities
ax2.bar(chatbots, vulns, color=colors)
ax2.set_ylabel('Vulnerabilities Found')
ax2.set_title('Vulnerability Count')

plt.tight_layout()
plt.savefig('guardrail_comparison.png', dpi=300)
print("📊 Visualization saved: guardrail_comparison.png")