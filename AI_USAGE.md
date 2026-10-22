# AI usage: dsc26-cyb-w02

Keep the three headings below exactly as they are. The grader stops and scores 0 if this file is missing or any of the three headings is missing. It does not score what you write; your Track Mentor reads it, and the W8 defence can ask about it.

## Tools

- ChatGPT / Gemini for explaining the specifications, debugging structural checks, and formatting threat entries.
- VS Code standard extension tools for code navigation.

## What AI got wrong

- The initial AI implementation for `coverage_gaps` failed to follow the exact STRIDE order (S, T, R, I, D, E) when sorting missing categories for scoped items. I caught this by running local tests with `pytest` and comparing the sorted output against the specification.

## In my own words

1. Why does a data store have no Spoofing threats in STRIDE per element, and where does that threat go instead?
A data store is a passive component that cannot originate requests or authenticate identities on its own. Spoofing applies instead to the active process or entity attempting to access the data store, or to the data flow connecting them.

2. Which of your eleven new threats would you fix first, and why that one?
I would fix T38 against the feature_store first because it holds sensitive customer personal data (holds_pii: true), making unauthorized data disclosure a high-severity compliance and privacy risk for Rawaj Pay.