
### General Notes

> Holds configuration information, or specific settings to each [[Environment]].
> Present in the Config folder in a [[NodeJs]] project.
> Can me managed by the [[Config Module]].

---

### Config Folder

* `default.json` : Has the default configuration settings.
* `development.json` : Has the settings for the development environment and overrides the default configuration.
* `production.json` : Has the settings for the production environment and overrides the default configuration.
* `custom-environment-variables.json` : Has the fields that are secrets that should be stored in the machines environment variables. It holds the values of the fields as environment variables names.

>`custom-environment-variables.json`
```JSON
{
	"password": "app_password"
}
```

Where `app_password` is an environment variable set in the machine itself.

---
