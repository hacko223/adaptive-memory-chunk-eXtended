#!/usr/bin/env python3
"""Basic example of using amcx for developers"""

from amcx import SmartMemory

# Create memory (no mirror = smaller file)
memory = SmartMemory("chat_example.amcx", use_mirror=False)

# Simulate conversation
memory.append("User: Hello, tell me about the universe")
memory.append("ai: The universe is vast and mysterious, with billions of galaxies...")
memory.append("user: And what about black holes?")
memory.append("ai: Black holes are regions of spacetime...")

# Search for relevant context
print("Searching for 'universe':")
results = memory.search("universe", max_results=2)
for r in results:
    print(f"  - {r[:50]}...")

# Get recent messages
print("\nLast 2 messages:")
recent = memory.get_recent(2)
for r in recent:
    print(f"  - {r[:50]}...")

# Stats
print(f"\nTotal messages: {memory.count_messages()}")
print(f"Size on disk: {memory.size_on_disk()/1024:.1f} KB")
#god loves you