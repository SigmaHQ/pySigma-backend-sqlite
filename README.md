![Tests](https://github.com/wagga40/pySigma-backend-sqlite/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/wagga40/2ec45ded898fa11f2c42bcb9d2b163cf/raw/test.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

# pySigma SQLite Backend

This is the SQLite backend for pySigma. It provides the package `sigma.backends.sqlite` with the `sqliteBackend` class.

This backend also aims to be compatible with [Zircolite](https://github.com/wagga40/Zircolite) which uses **pure SQLite queries** to perform SIGMA-based detection on EVTX, Auditd, Sysmon for linux, XML or JSONL/NDJSON Logs.

It supports the following output formats:

* **default**: plain SQLite queries
* **zircolite** : SQLite queries in JSON format for Zircolite

This backend is currently maintained by:

* [wagga](https://github.com/wagga40/)

## Supported Features

### Sigma Modifiers

| Modifier | Description | SQLite Implementation |
|----------|-------------|----------------------|
| `contains` | Substring matching | `LIKE '%value%'` |
| `startswith` | Prefix matching | `LIKE 'value%'` |
| `endswith` | Suffix matching | `LIKE '%value'` |
| `all` | All values must match | Multiple `AND` conditions |
| `re` | Regular expressions | `REGEXP` |
| `cidr` | CIDR network matching | Expanded to `LIKE` patterns |
| `cased` | Case-sensitive matching | `GLOB` |
| `fieldref` | Compare two fields | `field1=field2` or with `LIKE` for startswith/endswith/contains |
| `exists` | Field existence check | `field = field` |
| `gt`, `gte`, `lt`, `lte` | Numeric comparisons | `>`, `>=`, `<`, `<=` |
| `hour`, `minute`, `day`, `week`, `month`, `year` | Timestamp part extraction | `strftime()` |

### Correlation Rules

The backend supports Sigma correlation rules with the following types:

| Correlation Type | Description |
|-----------------|-------------|
| `event_count` | Count events matching conditions |
| `value_count` | Count distinct field values |
| `temporal` | Events from multiple rules occurring within a timespan |
| `temporal_ordered` | Events occurring in a specific order within a timespan |
| `value_sum` | Sum of field values |
| `value_avg` | Average of field values |

Correlation rules support `group-by` for grouping results and `timespan` for temporal constraints.

#### SQLite Requirements for Correlation

For correlation rules to work properly, your SQLite database must meet the following requirements:

| Requirement | Description |
|-------------|-------------|
| **Timestamp field** | Required for temporal correlations. Must be in a format compatible with SQLite's `julianday()` function (ISO8601, Julian day number, or Unix timestamp) |

**Configurable Parameters:**

The backend provides configurable parameters for correlation queries:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `timestamp_field` | `timestamp` | Field name containing the event timestamp |

**Example usage with custom parameters:**

```python
backend = sqliteBackend(correlation_methods=["default"])
backend.timestamp_field = "event_time"
```

**Notes:**
- The timestamp field is used with `julianday()` for time difference calculations in temporal correlations
- For multi-rule correlations (`temporal`, `temporal_ordered`), the backend automatically adds a `sigma_rule_id` column to identify which rule matched each event
- Timespan values are converted to seconds internally for comparison

### Other Features

* **NULL value handling**: `field: null` → `field IS NULL`
* **Boolean values**: `true`/`false` support
* **Field name quoting**: Special characters in field names are quoted with backticks
* **Wildcard escaping**: Proper escaping of `%` and `_` characters in values

## Known issues/limitations

* Full text search support will need some work and is not a priority since it needs virtual tables on SQLite side

# Quick Start 

## Example script (default output) with sysmon pipeline

### Add pipelines 

```shell
poetry add pysigma-pipeline-sysmon
poetry add pysigma-pipeline-windows
```

### Convert a rule

```python 
from sigma.collection import SigmaCollection
from sigma.backends.sqlite import sqlite
from sigma.pipelines.sysmon import sysmon_pipeline
from sigma.pipelines.windows import windows_logsource_pipeline

from sigma.processing.resolver import ProcessingPipelineResolver

# Create the pipeline resolver
piperesolver = ProcessingPipelineResolver()
# Add pipelines
piperesolver.add_pipeline_class(sysmon_pipeline()) # Syssmon  
piperesolver.add_pipeline_class(windows_logsource_pipeline()) # Windows
# Create a combined pipeline
combined_pipeline = piperesolver.resolve(piperesolver.pipelines)
# Instantiate backend using the combined pipeline
sqlite_backend = sqlite.sqliteBackend(combined_pipeline)

rule = SigmaCollection.from_yaml(
r"""
    title: Test
    status: test
    logsource:
        category: test_category
        product: test_product
    detection:
        sel:
            fieldA: valueA
            fieldB: valueB
        condition: sel
""")

print(sqlite_backend.convert(rule)[0])

```

## Running

```shell
poetry run python3 example.py
```
