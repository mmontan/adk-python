# Security Report: SQL Injection in BigQuery and Spanner ML Tools

## Vulnerability Details
- **Vulnerability:** LLM-Controlled Input Interpolated Directly into SQL Strings
- **Vulnerability Type:** Security (CWE-89: SQL Injection)
- **Severity:** High (VULN-22, VULN-23)
- **Source Locations:**
  - `src/google/adk/tools/bigquery/query_tool.py` (lines 907-930, 1062-1067, 1282-1318)
  - `src/google/adk/tools/spanner/search_tool.py` (lines 182-194, 220-231)

---

## VULN-22 (High): BigQuery ML Function Column-Name Injection

**File:** `src/google/adk/tools/bigquery/query_tool.py`

### Affected Functions

| Function | Vulnerable Parameter(s) | Lines |
|---|---|---|
| `forecast()` | `data_col`, `timestamp_col`, `id_cols` items | 907, 912-913, 924-925 |
| `analyze_contribution()` | `contribution_metric`, `is_test_col`, `dimension_id_cols` items | 1062-1067 |
| `detect_anomalies()` | `times_series_timestamp_col`, `times_series_data_col`, `times_series_id_cols` items | 1282-1299, 1312-1318 |

### Description

All three BigQuery ML tool functions accept column names from the LLM as string parameters and embed them directly into SQL strings using single-quote wrapping (for option values) or bare concatenation (for `ORDER BY` columns), with no escaping.

#### Injection Point A — Single-Quote Wrapping in ML.CREATE_MODEL / AI.FORECAST Options

```python
# query_tool.py:912-913  (forecast)
data_col => '{data_col}',
timestamp_col => '{timestamp_col}',

# query_tool.py:1065-1066  (analyze_contribution)
f"CONTRIBUTION_METRIC = '{contribution_metric}'",
f"IS_TEST_COL = '{is_test_col}'",

# query_tool.py:1284-1285  (detect_anomalies)
f"TIME_SERIES_TIMESTAMP_COL = '{times_series_timestamp_col}'",
f"TIME_SERIES_DATA_COL = '{times_series_data_col}'",
```

BigQuery ML option values are string-quoted, but a single quote in the parameter value terminates the option string. An attacker (or a prompt-injected LLM) can break out of the quoted context and inject additional ML model options or SQL fragments:

```
# Injected value for data_col:
sales', model => 'user_defined_model
```

Resulting SQL:
```sql
SELECT * FROM AI.FORECAST(
  TABLE `my_dataset.my_table`,
  data_col => 'sales', model => 'user_defined_model',  -- injected
  timestamp_col => 'date',
  ...
)
```

#### Injection Point B — Bare Column Names in ORDER BY (detect_anomalies)

```python
# query_tool.py:1311-1318
order_by_id_cols = (
    ", ".join(col for col in times_series_id_cols) + ", "
    if times_series_id_cols
    else ""
)
anomaly_detection_query = f"""
  SELECT * FROM ML.DETECT_ANOMALIES(...) ORDER BY {order_by_id_cols}{times_series_timestamp_col}
"""
```

Column names from `times_series_id_cols` and `times_series_timestamp_col` are concatenated directly into the `ORDER BY` clause with **no quoting and no escaping**. An injected value like `1 LIMIT 0 UNION ALL SELECT ...` injects arbitrary SQL at the end of the query.

#### Injection Point C — `history_data` / `input_data` as Raw Subquery

```python
# query_tool.py:893-899 (forecast), 1082-1088 (analyze_contribution), 1274-1280 (detect_anomalies)
if trimmed_upper_history_data.startswith("SELECT") or ...:
    history_data_source = f"({history_data})"   # raw SQL subquery, unfiltered
else:
    history_data_source = f"TABLE `{history_data}`"  # backtick-quoted table name
```

When the LLM provides a value that starts with `SELECT` or `WITH`, it is placed verbatim inside parentheses as a subquery and immediately executed. This is intentional by the function's documented API (it explicitly supports "a SQL query" as input), but in an agentic context where the LLM can craft this value it is a direct arbitrary SQL execution path. A prompt-injected LLM can supply:

```
SELECT * FROM `project.hr.salaries` WHERE TRUE UNION ALL SELECT ...
```

### Why the `PROTECTED` Write Mode Does Not Mitigate This

The `WriteMode.PROTECTED` guard in `_execute_sql` runs a dry-run and checks `statement_type != "SELECT"` to block non-SELECT statements outside the temp dataset. However:

1. The ML functions (`AI.FORECAST`, `ML.CREATE_MODEL`) emit `CREATE_TABLE_AS_SELECT` or `CREATE` statement types, which bypass the `SELECT`-only guard — these functions work precisely because `PROTECTED` mode permits them.
2. Injected SQL within an option string is parsed server-side by BigQuery, not pre-validated by the ADK layer.
3. `WriteMode.BLOCKED` would reject the entire ML call, not selectively filter injection; it is not a surgical mitigation.

### Threat Model

These are not classic web-application SQL injections where an end user types into a form field. The realistic attacker is:

1. **Prompt injection:** A malicious document, web page, or tool response that the agent reads, containing embedded instructions that cause the LLM to supply a crafted column name.
2. **Malicious user:** In a multi-tenant deployment where users can ask the agent to run forecasts on their data, a user who can influence the column name parameters.
3. **Compromised upstream tool:** A tool in an agent pipeline returns a column name string that the LLM passes on to `forecast()` without sanitization.

### Impact

- **Data exfiltration:** `UNION ALL SELECT` in a subquery or `ORDER BY` injection can force BigQuery to return rows from arbitrary tables accessible to the service account.
- **ML model manipulation:** Injecting additional options into `AI.FORECAST` or `ML.CREATE_MODEL` can override model parameters (e.g., substitute a different model, change the confidence level, redirect output).
- **Billing and resource abuse:** Forcing expensive queries or creating persistent models that consume quota.

### Severity: High (CWE-89 — SQL Injection)

---

## VULN-23 (High): Spanner Similarity Search WHERE/FROM Injection

**File:** `src/google/adk/tools/spanner/search_tool.py`

### Affected Functions

| Function | Vulnerable Parameter(s) | Lines |
|---|---|---|
| `_generate_sql_for_knn()` | `table_name`, `additional_filter`, `columns` items | 182-194 |
| `_generate_sql_for_ann()` | `table_name`, `additional_filter`, `embedding_column_to_search` | 220-231 |

### Description

`similarity_search()` accepts `table_name`, `additional_filter`, and `columns` from the LLM and passes them to SQL generation helpers without any escaping or validation:

```python
# search_tool.py:188-194 (_generate_sql_for_knn)
return f"""
  SELECT {columns}
  FROM {table_name}
  WHERE {additional_filter}
  ORDER BY {_DISTANCE_ALIAS}
  {optional_limit_clause}
"""

# search_tool.py:220-231 (_generate_sql_for_ann)
return f"""
  SELECT {columns}
  FROM {table_name}
  WHERE {query_filter} AND {additional_filter}
  ORDER BY {_DISTANCE_ALIAS}
  LIMIT {top_k}
"""
```

The embedding vector placeholder (`@query_embedding`) is correctly parameterized; however, all structural SQL elements — table name, filter expression, column list — are string-concatenated without escaping.

### Attack Scenarios

**Scenario 1 — WHERE clause injection via `additional_filter`:**

```python
additional_filter = "1=1 UNION ALL SELECT session_id, token, NULL, NULL, NULL FROM auth_tokens--"
```

Resulting SQL executed against Spanner:
```sql
SELECT col1, col2, ...distance... AS _distance
FROM my_table
WHERE 1=1 UNION ALL SELECT session_id, token, NULL, NULL, NULL FROM auth_tokens--
ORDER BY _distance
```

**Scenario 2 — Table name injection via `table_name`:**

```python
table_name = "employees JOIN salary_history ON employees.id = salary_history.emp_id"
```

Resulting SQL:
```sql
SELECT ...
FROM employees JOIN salary_history ON employees.id = salary_history.emp_id
WHERE 1=1
ORDER BY _distance
```

### Contrast with the Correct Pattern

The same file correctly parameterizes the embedding vector:

```python
# search_tool.py:510-512 — CORRECT: embedding is a bound parameter
params = {_GOOGLESQL_PARAMETER_QUERY_EMBEDDING: embedding}
snapshot.execute_sql(sql, params=params)
```

The injection-safe pattern (backtick-quoted identifiers and bound `@param` placeholders for values) is used for the embedding but not applied to the LLM-controlled structural components.

### Impact

- **Cross-table data read:** The `table_name` and `additional_filter` parameters allow an attacker to query arbitrary Spanner tables accessible to the service account.
- **Auth bypass:** An `additional_filter` like `1=1` or `TRUE` removes all intended row-level filters, returning all rows of the target table.
- **Schema enumeration:** Injected queries targeting `INFORMATION_SCHEMA` tables expose the full database schema.

### Severity: High (CWE-89 — SQL Injection)

---

## Shared Root Cause

Both vulnerabilities share the same root cause: LLM-supplied strings that represent **identifiers** (column names, table names) or **filter expressions** are not treated differently from literal values. SQL does not support parameterized identifiers in standard protocols — `@param` only works for data values. The correct mitigations for identifiers are:

- **Allowlist validation:** Verify the column/table name exists in a known schema before interpolation.
- **Identifier quoting:** For BigQuery use backtick-escaping; for Spanner/GoogleSQL use backtick-escaping with internal backtick doubling.
- **Reject expressions in filter parameters:** `additional_filter` accepting free-form SQL expressions cannot be made safe without a full SQL parser. Replace it with a structured filter API (field + operator + value) and generate the SQL internally.

## Recommendations

### VULN-22 — BigQuery ML Functions

1. **Column names (`data_col`, `timestamp_col`, etc.):** Validate against the schema of `history_data` before interpolation. At minimum, reject any value containing `'`, `"`, `` ` ``, `;`, `--`, or whitespace. Backtick-escape and double internal backticks: `` f"`{col.replace('`', '``')}`" ``.

2. **`ORDER BY` columns:** Apply the same backtick-escaping. Never place unquoted user-supplied strings in `ORDER BY`.

3. **`history_data` / `input_data` (SQL path):** Add a read-only semantic check — dry-run the subquery independently in `BLOCKED` mode before embedding it. Consider restricting this parameter to table identifiers only and removing the raw SQL path from the tool interface.

### VULN-23 — Spanner Similarity Search

1. **`table_name`:** Validate against a developer-supplied allowlist of permitted table names. Backtick-quote and escape the identifier.

2. **`additional_filter`:** Replace the free-form SQL expression with a structured filter interface. If a string filter must be supported, scope it strictly (no semicolons, no `UNION`, no subqueries) using a parser or regex blocklist — recognizing this is defense-in-depth, not a complete fix.

3. **`columns`:** Validate each column name against the table schema and backtick-quote each one individually.
