w### General Notes

KAPE, or *Kroll Artifact Parser and Extractor*, is a [[Rapid Triage]] tool used for collection and analysis of digital evidence on Windows systems.
- KAPE works using *Targets* and *Modules*.

##### Targets

**Targets** are used to specify what evidence to collect from the system or image.
- The system is scanned and copies of only the relevant artifacts are taken to a designated location.
- They are [[XML]] files that define files, folders, or [[Windows Registry|Registry Keys]] to collect for analysis.

Target files have a `.tkape` extension and can be found in the `\KAPE\Targets\` directory.
- These files contain the locations and file masks that specify the information that is to be collected.

There are also *Compound Targets* which are combinations of several *Targets*, which can accelerate the collection process by gathering multiple files defined across various Targets at once.
- They are found in the `\KAPE\Compound\`directory, and the `KapeTriage.tkape` file specifies several *Target* files that are referenced.

##### Modules

**Modules** are used to parse and analyze the collected artifacts to generate reports for examination.
- They are [[XML]] files that specify how to parse or analyze the collected artifacts to produce summaries, timelines, or reports.

---
