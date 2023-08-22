![Tests](https://github.com/wagga40/pySigma-backend-sqlite/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/wagga40/2ec45ded898fa11f2c42bcb9d2b163cf/raw/test.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

# pySigma SQLite Backend

### **PLEASE NOTE THAT THIS IS A WORK IN PROGRESS**

This is the SQLite backend for pySigma. It provides the package `sigma.backends.sqlite` with the `sqliteBackend` class.

For now, this backend aims to be compatible with [Zircolite](https://github.com/wagga40/Zircolite) which uses pure SQLite queries to perform SIGMA-based detection on EVTX, Auditd, Sysmon for linux, XML or JSONL/NDJSON Logs.

It supports the following output formats:

* **default**: plain SQLite queries
* **zircolite** : SQLite queries in JSON format for Zircolite

This backend is currently maintained by:

* [wagga](https://github.com/wagga40/)

## Known issues 

* Full text search support will need some work and is not a priority since it needs virtual tables on SQLite side
* In a future update, changing table name will be handled by a backend option

# Quick Start 

## Example script (default output) with sysmon pipeline

```python 
from sigma.collection import SigmaCollection
from sigma.backends.sqlite import sqlite
from sigma.pipelines.sysmon import sysmon_pipeline
from sigma.pipelines.windows import windows_logsource_pipeline

from sigma.processing.resolver import ProcessingPipelineResolver

# Create the pipeline resolver
piperesolver = ProcessingPipelineResolver()
# Add pipelines
piperesolver.add_pipeline_class(sysmon_pipeline()) # Sysmon  
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
# Change to sqlite_backend.convert_rule(rule, "zircolite")[0] to use "zircolite" format

```

## Running

```shell
poetry poetry run python3 example.py
```
