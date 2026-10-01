##### **Planning Logging**

- What will you log, and for what (asset scope and logging purpose)?
    - Is additional commitment or effort required to achieve the purpose (requirements related to the purpose)?
- How much are you going to log (detail scope)?
- How much do you need to log?
- How are you going to log (collection)?
- How are you going to store collected logs?
    - Is there a standard, process, legislation, or law that you must comply with due to the data you log?
- How are you going to protect the logs?
- How are you going to analyze collected logs?
- Do you have enough resources and workforce to do logging?
- Do you have enough budget to plan, implement and maintain logging?

##### **Logging Principles**

|   |   |
|---|---|
|**Collection**|- Define the logging purpose.<br>- Collect what you will need and use.<br>- Do not collect irrelevant data.<br>- Avoid log noise.|
|**Format**|- Log at the correct level and detail.<br>- Implement a consistent log format.<br>- Ensure that timestamps in logs are accurate and synchronised.|
|**Archiving and Accessibility**|- Define log retention policies and implement them.<br>- Store log data and make sure the important part is available for analysis. <br>- Create backups of stored log data and used systems.|
|**Monitoring and Alerting**|- Create alerts and notifications for important and noteworthy cases.<br>- Focus on actionable alerts and avoid noise.|
|**Security**|- Protect logs by implementing access controls.<br>- Implement encryption if required.<br>- Use a dedicated log management solution.|
|**Continuous Change**|- Logging sources, types, and messages are constantly changing and being updated.<br>    - Be open to continuous change.<br>- Train your personnel.|

##### **Logging Challenges**

|   |   |
|---|---|
|**Data Volume  <br>and Noise**|- Having multiple data sources to deal with.<br>- Differences in the log volumes created by applications.<br>    - Some applications generate an insufficient amount of logs.<br>    - Large-scale applicants could generate massive log volumes.  <br>        <br>- Some logs can provide non-essential data and make the identifying process difficult.|
|**System Performance  <br>and Collection**|- Log collection can slow down the system's performance.<br>- Systems are not always "state of the art".  <br>    - Some "sensitive" or "ancient" systems are impossible to touch.  <br>        <br>- Deployment and optimisation challenges.<br>    - Managing system and agent version updates and synchronisation in large-scale networks is overwhelming.|
|**Process and Archive**|- Having multiple data formats to deal with it.<br>    - Parsing different data sources and formats is time-consuming and error-prone.<br>- Balancing the log retention can be challenging.<br>    - Especially when dealing with many compliance regulations and standards.|
|**Security**|- Ensuring data security is a task/challenge in itself.|
|**Analysis**|- Combining, correlating, and analysing data from multiple sources to understand the context of an incident is a time-consuming process that requires significant computing resources and expertise.  <br>    - Achieving this in real-time is also another challenge in the same scope.<br>    - Avoiding false positives/negatives is overwhelming.|
|**Misc**|- Lack of planning and roadmap.<br>- Lack of financial resources/budget.<br>- Lack of implementation scenarios, playbooks, and exercises.<br>- Lack of technical skills to implement, maintain, and analyse.<br>- Focusing on log collection instead of the analysis phase.<br>- Ignoring human factors and potential system errors.|

---
