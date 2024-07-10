
### General Notes

Way to connect 2 or more devices, it is a software interface with specifications on how to do so.

> Consumable APIs are APIs are those accessible to people outside organizations for consumer use.

___

### RESTful API

A type of APIs where servers do not keep any information about the state. The client is responsible for keeping state.

Using **requests** and changing their paths, types, and bodies to perform actions.
- The path is usually called the **endpoint**.
- Using [[HTTP]] verbs, we can change the request function with different bodies.
- Receive **response** with the data needed and an [[HTTP]] status code.

___

### Good Practice

- Use nouns and no verbs in the endpoints 
- APIs should be versioned to avoid confusion
- Lists should have limits to avoid errors `.../?limit=10`
- Response should include status codes and the data format
- Error payloads should include messages

---
