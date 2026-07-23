# Demo source

Vendored from https://github.com/theredguild/damn-vulnerable-defi (the Damn
Vulnerable DeFi wargame by @tinchoabbate, maintained by The Red Guild), the
canonical set of offensive DeFi security challenges. Cloned into the Hawk-i demo
corpus so scan and the deep agent can be exercised against real DeFi challenge
code. Scans target src/ (the challenge contracts); lib/ holds vendored audited
dependencies (solmate, solady, uniswap-v3) and is not the subject under test.
