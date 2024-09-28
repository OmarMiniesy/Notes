### Brief Introduction

**Serialization** is the process of converting information that is in a complex structure, such as an object, into a simpler format that can be easily sent, received, and read as a stream of bytes.
- This process must ensure that the *state* of the information, remains the same.

Most of the time, the complex information represents an *object*, a structure that has attributes, and each attribute has its own value.
- A *class* defines an object's attributes and method.

**Deserialization** is the reverse process, the process of converting back from the stream of bytes to the original information and its state.
- Reverting back from bytes to an object with all of its attributes and values in the same state. 

> Serialization and Deserialization is offered by default in many languages, and the process of serialization itself changes amongst them. In Python, it's called **pickling**, and in Ruby it's called **marshalling**.

---
### General Notes

As with almost all web based vulnerabilities, the main source of danger comes from the user input.
- **Insecure Deserialization** happens when a website performs a deserialization process on user-controlled data.
- An attacker can utilize this, and pass malicious serialized information that can harm the application.

The vulnerability is dangerous because websites will deserialize any serialized object and instantiate it, even if the object that was produced is of a class that is not expected by the website.
- Objects that are of an unexpected class will cause errors, or exceptions, but the damage might have already been done.
- The deserialization process itself can launch the attack, and it is not required by the website to interact with the produced object.

---
### Identifying Serialization

To pinpoint insecure deserialization vulnerabilities, monitor data flow and try to recognize any data that is passed in a serialized manner.
- Serialized data format is different from language to language.
- Once it is identified, tests should begin to see if it can be controlled.
##### PHP Serialization

PHP uses 2 functions, `serialize()` and `unserialize()`.
- If source code access is given, searching for the `unserialize()` function is essential.

PHP serialization is in a human readable format that follows this order:
1. First, letters are used to represent the data type.
2. Then, a number is used to represent the length of the data entry, that is the object name, attribute name, or value name.
3. Finally, the value of the entry is written that has the length specified above.

Important characters:
- `:` colons are used as separators.
- `{}` braces are used to encompass the state of the object. There is a number before the braces to indicate the number of attributes of the object.
- `;` semicolon is used to separate the attributes of the object.

For example, this is the `User` object, and it has 2 attributes, `name` and `isLoggedIn`:
```
$user->name = "carlos"; 
$user->isLoggedIn = true;
```

Is serialized into:
```
O:4:"User":2:{s:4:"name":s:6:"carlos"; s:10:"isLoggedIn":b:1;}
```

The object:
- The first letter is `O`, or the *object* datatype.
- Followed by `4`, the length of the object name, `User`, which has 4 characters.
- Followed by the value, `User`.
- Right after finishing the object, specify the number of attributes, `2`, and then open braces.

The attributes:
- For each attribute, the data type character, where *string* is `s` and *Boolean* is `b`.
- Followed by the length of the attribute name, `4` for `name` and `10` for `isloggedin`.
- Followed by the name of the attribute.
- Followed by the size of the value of the attribute.
- Followed by the value of the attribute.

##### Java Serialization

This is harder to read, as it is in binary.
- However, Java objects when serialized always begin with the bytes `ac ed` in hex and `rO0` in base64.

Classes in Java that implement the interface `java.io.Serializable` can be serialized and deserialized.
- The function `readObject()` is responsible for reading and deserializing data.

---
### Exploiting Insecure Deserialization

