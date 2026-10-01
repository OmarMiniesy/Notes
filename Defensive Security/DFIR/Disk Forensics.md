### General Notes

This is the analysis and examination of digital evidence from storage media.
- It mainly focuses on the *acquisition, analysis, and recovery* of data from storage media.

Some of the key aspects of disk forensics include:
- **Data Acquisition**: Creating copy of the storage device without altering. Done with cryptographic hashes to ensure matching images are created.
- **Data Recovery**: Retrieving deleted, hidden, or damaged data by recovering *file fragments*, *slack space* (unused storage space that contains residual data), or *unallocated space*. Recovery can also be done on emails to obtain information on headers, content, and attachments in a process called *email carving*.
- **File System Analysis**: Examining the structure of the file system and establishing timelines using the *MAC(b) (Modification, Access, Creation, and birth)* times. Check out [[File System#MAC(b) Times in NTFS|MAC in NTFS]].
- **Artifact Examination**: This is evidence such as browsing history, installed programs, recently accessed files. This can be obtained from system logs, [[Windows Registry|Registry Hives]] and other OS related artifacts.

> A tool used in disk forensics is Autopsy.

---
