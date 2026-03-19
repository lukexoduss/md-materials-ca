### Birthday Paradox

The birthday paradox gets its name from a surprising statistical fact about birthdays in groups of people.

The paradox asks: How many people do you need in a room before there's a 50% chance that two of them share the same birthday?

Most people intuitively guess a much higher number than the actual answer, which is only 23 people. With just 23 people, there's approximately a 50% probability that at least two share a birthday. With 70 people, the probability exceeds 99.9%.

This feels paradoxical because:
- There are 365 possible birthdays
- 23 seems far too small compared to 365
- People often think you'd need around 183 people (half of 365)

**Why the intuition fails:**

The key insight is that we're not asking "what's the chance someone shares *your specific* birthday?" Instead, we're asking "what's the chance *any two people* share a birthday?" 

With 23 people, there are 253 possible pairs of people (calculated as 23 × 22 ÷ 2). Each pair is an opportunity for a matching birthday, which is why the probability grows much faster than intuition suggests.

**Connection to hash collisions:**

The same mathematics applies to hash functions. Finding a collision (any two inputs that hash to the same output) is like finding any two people with the same birthday—much easier than finding a specific collision, just as it's easier to find any matching pair than to find someone who shares *your* birthday specifically.

### Pigeonhole Principle

The **pigeonhole principle** is a fundamental concept in mathematics that states:

**If you have more pigeons than pigeonholes, at least one pigeonhole must contain more than one pigeon.**

More formally: If n items are placed into m containers, and n > m, then at least one container must contain more than one item.

#### Simple Examples

- **10 pigeons, 9 holes** → At least one hole contains 2+ pigeons
- **367 people** → At least two share a birthday (since there are only 366 possible days including leap day)
- **13 people** → At least two were born in the same month

#### Relation to Hash Functions

For hash functions, the pigeonhole principle guarantees that **collisions must exist**:

- If a hash function maps an infinite (or very large) input space to a finite output space (e.g., 256-bit outputs = 2^256 possible values)
- Then multiple different inputs **must** map to the same hash output
- Collisions are mathematically inevitable

#### Birthday Paradox vs. Pigeonhole Principle

These are related but different concepts:

**Pigeonhole Principle:**
- Tells you collisions *must exist* once you exceed the number of possible outputs
- Deterministic and guaranteed
- For 256-bit hash: After 2^256 + 1 inputs, you're *guaranteed* a collision

**Birthday Paradox:**
- Tells you collisions become *probable* much sooner
- Probabilistic, not guaranteed
- For 256-bit hash: After ~2^128 attempts, you have ~50% chance of finding a collision

The birthday paradox is why hash functions need such large outputs—the pigeonhole principle kicks in at 2^n, but practical attacks succeed around 2^(n/2).