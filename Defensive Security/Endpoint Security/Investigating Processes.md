## Windows

To investigate processes on Windows devices, the following tools can be used:

> Checkout [[Windows Processes]] for more information on common windows processes.

###### Task Manager

There is a `processes` tab that lists the processes running on the system. It has columns can be added such:
- *Type* of the process, like Apps, Background Processes, or Windows Processes.
- *Publisher* of the process, which is the author of the program.
- *PID* is the process identifier.
- *Process Name*.
- *Command Line*: The full command that is used to launch the process.
- *CPU* and *memory* consumption.

There is also the `details` tab which can have extra columns added like the *image path name*, which is the path to the executable.
- All the columns that can be added are in this [list](https://www.howtogeek.com/405806/windows-task-manager-the-complete-guide/#:~:text=Here%27s%20what%20every%20possible%20column%20means%3A)
###### [[Process Hacker]]

###### [[Sysinternals#Process Utilities|Sysinternals - Process Explorer]]

There also exist other command line options to analyze processes like:
- `tasklist`
- `Get-Process`
- `ps`
- `wmic`

---
