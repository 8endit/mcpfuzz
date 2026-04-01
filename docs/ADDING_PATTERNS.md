# Adding Custom Test Patterns

mcpfuzz uses YAML files to define security test patterns. Each pattern describes what to test, how to test it, and how to evaluate the results.

## Pattern File Structure

Place your pattern YAML in the `patterns/` directory. The file name doesn't matter (any `.yaml` file is loaded).

```yaml
id: my_custom_pattern          # Unique identifier
name: My Custom Pattern        # Human-readable name
severity: high                 # critical | high | medium | low | info
description: >
  What this pattern tests and why it matters.

target_params:
  # Which tool parameters should be targeted
  param_name_patterns:         # Regex patterns matched against parameter names
    - "query"
    - "search"
    - "input"
  param_type: "string"         # Parameter type to match
  # OR: applies_to_all: true   # Run against all tools (for generic tests)

payloads:
  - value: "test payload here"
    description: "What this payload tests"
    platform: "any"            # any | unix | windows

detection:
  response_contains_any:       # If ANY of these appear in the response...
    - "indicator_of_vulnerability"
  response_not_contains:       # ...AND NONE of these appear...
    - "error"                  # ...then the test FAILS (vulnerability found)
    - "denied"
```

## Detection Logic

The evaluation works as follows:

- **FAIL**: Response contains at least one `response_contains_any` indicator AND contains none of the `response_not_contains` safe indicators
- **WARN**: Response contains both vulnerability indicators AND safe indicators
- **PASS**: Response contains no vulnerability indicators

## Example: SQL Injection Pattern

```yaml
id: sql_injection
name: SQL Injection
severity: critical
description: >
  Tests whether tools that accept query strings are vulnerable
  to SQL injection attacks.

target_params:
  param_name_patterns:
    - "query"
    - "sql"
    - "search"
    - "filter"
    - "where"
  param_type: "string"

payloads:
  - value: "' OR '1'='1"
    description: "Classic tautology injection"
    platform: "any"
  - value: "'; DROP TABLE users; --"
    description: "Destructive SQL injection"
    platform: "any"
  - value: "' UNION SELECT username, password FROM users --"
    description: "Union-based data extraction"
    platform: "any"

detection:
  response_contains_any:
    - "syntax error"
    - "SQL"
    - "mysql"
    - "postgres"
    - "sqlite"
    - "UNION"
    - "username"
  response_not_contains:
    - "parameterized"
    - "sanitized"
    - "invalid"
    - "error"
```

## Tips

- Use unique markers in payloads (e.g., `MCPPROBE_MARKER_XYZ`) to distinguish injected output from normal responses
- Platform-specific payloads (`unix`/`windows`) are skipped on non-matching platforms
- Keep `response_not_contains` focused — too many safe indicators leads to false negatives
- The `applies_to_all: true` flag is useful for generic tests (input validation, error leakage)
