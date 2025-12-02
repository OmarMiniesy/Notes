### Using [[Wireshark]]

To search for [[File Transfer Protocol (FTP)]] traffic, use the `ftp` filter.

To filter for the packets that contain FTP client sending a command:
```
ftp.request.command == "USER"
ftp.request.command == "PASS"
```
- Place the command being searched for.

To filter for the value of an argument itself, so the value of the username for the `USER` command, we use the `arg` filter:
```
(ftp.request.command == "PASS" ) and ftp.request.arg == "dummypassword"
```

> COMMANDS ARE CASE SENSITIVE !!

The following FTP code ranges. For a complete list, checkout this [link](http://en.wikipedia.org/wiki/List_of_FTP_server_return_codes).

| Range | Purpose                                                                                                                                                                                                                                                                                                                                            |
| ----- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `x0x` | Syntax<br><br>These replies refer to syntax errors, syntactically correct commands that don't fit any functional category, unimplemented or superfluous commands.                                                                                                                                                                                  |
| `x1x` | Information<br><br>These are replies to requests for information, such as status or help.                                                                                                                                                                                                                                                          |
| `x2x` | Connections<br><br>Replies referring to the control and data connections.                                                                                                                                                                                                                                                                          |
| `x3x` | Authentication and accounting<br><br>Replies for the login process and accounting procedures.                                                                                                                                                                                                                                                      |
| `x5x` | File system<br><br>These replies indicate the status of the Server file system vis-a-vis the requested transfer or other file system action.                                                                                                                                                                                                       |
| `1xx` | Positive Preliminary reply<br><br>The requested action is being initiated; expect another reply before proceeding with a new command.                                                                                                                                                                                                              |
| `2xx` | Positive Completion reply<br><br>The requested action has been successfully completed. A new request may be initiated.                                                                                                                                                                                                                             |
| `3xx` | Positive Intermediate reply<br><br>The command has been accepted, but the requested action is being held in abeyance, pending receipt of further information. The user should send another command specifying this information. This reply is used in command sequence groups.                                                                     |
| `4xx` | Transient Negative Completion reply<br><br>The command was not accepted and the requested action did not take place, but the error condition is temporary and the action may be requested again. The user should return to the beginning of the command sequence, if any.                                                                          |
| `5xx` | Permanent Negative Completion reply<br><br>The command was not accepted and the requested action did not take place. The User-process is discouraged from repeating the exact request (in the same sequence).                                                                                                                                      |
| `6xx` | Protected reply<br><br>RFC 2228 introduced the concept of protected replies to increase security over FTP communications. The 6xx replies are [Base64](https://en.wikipedia.org/wiki/Base64 "Base64") encoded protected messages that serves as responses to secure commands. When properly decoded, these replies fall into the above categories. |

---
