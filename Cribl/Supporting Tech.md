### GIT

See [[Git Commands]] for general Git concepts.
- Git version `1.8.3.1` or higher is mandatory.

Cribl Stream creates a local git repository to version-control all configurations.
- **Commit** button: Saves configuration changes to the local git repo, creating a version history entry. This does *not* apply changes to the live environment.
- **Deploy** button: Pushes the latest committed configuration to the worker nodes or agents in the environment.
- Forgetting to commit and deploy means changes exist only in the UI and are not persisted or applied.
- Because all changes are versioned in git, rolling back to any prior configuration state is possible by reverting to an earlier commit.

---
### JS

Cribl uses JavaScript expressions to manipulate and filter data inside pipeline functions.
- JS is used within functions such as the Eval function and custom code functions to read, transform, and write event fields.
- Event fields are accessed via the `__e` object. For example:
  ```js
  __e['new_field'] = __e['existing_field'].toUpperCase();
  ```
- This allows arbitrary field creation, deletion, type conversion, and conditional logic directly within a pipeline stage.

---
### Regex

See [[Regular Expressions]] for syntax reference.

Regular expressions are used throughout Cribl to extract fields and match patterns.
- **Event Breakers**: Regex patterns define how raw byte streams are split into discrete events (e.g., splitting on newlines, JSON array boundaries, or custom delimiters).
- **Capture functions**: Extract named fields from unstructured [[Logs|log]] text using capture groups — useful for parsing formats covered in [[Log Analysis]].
- **Route conditions**: Regex can be used in routing rules to direct events matching a pattern to a specific pipeline or destination.
- Used in both Stream and Edge.

---
### KQL

See [[SIEM]] — KQL is also the query language used in Microsoft Sentinel. See [[Log Analysis]] for common query patterns applied to security logs.

KQL (Kusto Query Language) is a read-only query language developed by Microsoft to query large datasets.
- Cribl Search uses KQL as its default search language.
- Queries are written as pipelines of operators separated by `|`. Basic structure:
  ```kql
  index
  | where field == "value"
  | project field1, field2
  | summarize count() by field1
  ```
- Common operators: `where` (filter), `project` (select fields), `extend` (add computed fields), `summarize` (aggregate), `order by` (sort).

---
### Knowledge Objects - [[Cribl Products|Stream & Edge]]

Configuration objects that can be defined once and reused across pipelines to process data faster and in different ways.
- To access: top navigation → Processing → Knowledge.
- Knowledge Objects are shared across all pipelines within the same worker group.

**Lookup**
- A comma-delimited (CSV) file used with the Lookup pipeline function to enrich events during processing.
- Fields in the incoming event are matched against columns in the lookup file, and matching rows add new fields to the event (e.g., mapping an IP address to a hostname or geo-location).

**Event Breakers**
- Define how raw incoming byte streams are split into discrete events before pipeline processing begins.
- Supported break strategies include: newline-delimited, JSON arrays, regex-based patterns, and timestamp-anchored splitting.
- Can be created, edited, deleted, searched, and tagged within the Knowledge section.

**Regex Libraries**
- Reusable collections of named regex patterns that can be referenced across multiple pipeline functions without redefining them each time.
- Cribl ships with built-in libraries of common patterns (e.g., for syslog, Apache access logs, Windows events). Custom patterns can be added.

---
