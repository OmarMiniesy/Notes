
Using the commands from [[Git Commands]].

___
### Push to Main Branch

1. `git add .`  adds all files in the folder to the wait line.
2. `git commit -m "message"`  commits all files that were added to the wait line.
3. `git push`  pushes all changes to the master branch.

---
### Pushing to Different Branch

###### Create the branch
1. Create the branch `git branch <branch-name>`.
2. Go to branch `git checkout <branch-name>`.
3. Add the branch to the remote repo `git push -u origin <branch-name>`.

###### Push to the branch

Same Commands as pushing to main branch but make sure that the branch needed is the one active.
- Use `git checkout <branch-name>` to switch to this branch.
___
### Notes

1. If [[gitignore]] file is present, then it will be added to the files on the wait line.

---
