
___

> using the commands from [[Git Commands]]

___

### Steps

1. `git add .`  adds all files in the folder to the wait line
2. `git commit -m "message"`  commits all files that were added to the wait line
3. `git push`  pushes all changes to the master branch

---

### Pushing to a Different Branch

1. Create the branch `git branch <branch-name>`
2. Go to branch `git checkout <branch-name>`
3. Add the branch to the remote repo `git push -u origin <branch-name>`
4. Repeat steps above.

___

### Notes

1. If [[gitignore]] file is present, then it will be added to the files on the wait line
