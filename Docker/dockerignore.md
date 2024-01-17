
### General Notes

> This a file similar to [[gitignore]]. 

Very beneficial to reduce image size and to avoid publishing dangerous files, such as the environment variables.

[Guide](https://shisho.dev/blog/posts/how-to-use-dockerignore/).

---

### Details

 > The file is called `.dockerignore` with no extensions.
 > Its presence is automatically detected by the build command given that it is located in the same directory as the [[Dockerfile]].
 
It specifies all the files we dont want placed into the [[Images]] whilst building it using the [[Dockerfile]]. 

Example: 
```dockerignore
**/node_modules/
```

---

