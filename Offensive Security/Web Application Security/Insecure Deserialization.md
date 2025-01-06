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

There are 2 ways of manipulating serialized objects;
- Edit the object in its byte stream form.
- Write a script in the language needed to create and serialize a new object.

> The idea is to change the data inside a serialized object in some way, and then pass this new malicious object into the website via a deserialization process

##### Modifying Object Attributes

Identifying a serialized object to store data, and then change the value of some of the attributes, and then re-send that data.
- If the server uses this data to give access to certain features, or identify users, then this new object can be used to gain unauthorized access.

It is essential that the new serialized object that was modified to be syntactically correct, so that when the server receives this object and deserializes it to use it, it properly executes what the attacker desires.

> However, this is not always the case if the serialized object has its authenticity first checked.

##### Modifying Data Types

Modifying the data types of serialized objects is especially common in `PHP` based logic due to the *loose comparison* `==` operator.
- The loose comparison operator when comparing string with integers, it tries to convert the string to an integer and compare them.

This loose comparison operator does the following:
- `5 == '5'` will result in *true*, since the string is converted to an integer. This is treated as `5 == 5`.
- `5 == "5 of something"` will result in *true*, where PHP converts the entire alphanumeric string to the first integer. The integer has to be the first character in the string. This is treated as `5 == 5`.
- For the number `0`, things change. `0 == "no numbers"` this returns *true* because there are no numbers in the string, hence, the entire string is treated as `0`.

> These conditions introduce dangerous logical flaws, hence, it is important to remember indicating the correct data type while serializing to take advantage.

##### Magic Methods

These are methods that are automatically called when an event occurs.
- They are identified by having double underscores before and/or after the function name.
```
__init__
__construct()
```

Magic methods automatically execute, meaning they are vulnerable if they take attacker controlled input.
- Some magic methods are executed during deserialization, such as `__wakeup()` in PHP and `readObject()` in Java.
- These methods depend on the class of the object, and sometimes, these methods can be overridden.

The methods for an object are defined by the class of that object.
- If the class can be changed by the attacker, then the attacker can influence which methods are called on the injected object.
- If deserializing functions do not check the data they are dealing with, then this is possible, allowing attackers to create objects of any arbitrary class.

To conduct an attack like that, the attacker should have access to the source code, and understand the different classes that exist.
- The attacker should then identify any deserialization magic methods if any exist, and check if they perform any dangerous operations.

> Source code of a file can be obtained by inserting a `~` after the filename. Check [[Information Disclosure#Source Code Disclosure Via Backup Files]].