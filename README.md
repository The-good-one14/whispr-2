# **Whispr**, the app that doesn't need your driver's license to work
## Whispr v2 is the successor of Whispr-chat, a web based chat app in python/html/css/js

### **Features:**
- **Secure asymmetric key encryption and signing:** The app uses ed25519 and x25519 for signing and encrypting messages respectively.
- **Forward secrecy:** a new temporary keypair and Nonce (number used once) is used for every message, effectively making hacking message history near-impossible.
- **Blind Server structure:** The server is made to only be able to view the minimum it needs, so your messages stay private.
- **Multible platform support:** (Eventually) the app will be avaible as TUI, website, and GUI app.
- **Direct messaging and group chats:** Group rooms will have a structure similar to Discord, where anyone can access it with the right name and key. Rooms are also able to be public, meaning no password/key is needed and anyone can access it.

- **save & private chat history:** Chat history is saved *locally*, meaning no one can access it except you.
- **No Identification needed:** setting up an account requires absolutely zero personal info, an account is completely based and dependent on an ed25519 keypair instead of a traditional username & password

#### **Disclaimer:** some of these features are post-mvp and may not be implemented yet.

#### **Another Disclaimer:** the project is pre-alpha, nothing works rn.

### **Tech stack**:
- 100% pure rust
- cryptography uses ed25519-dalek and x25519-dalek together with chacha20poly1305 and hkdf
- serde and postcard for serialization
- full dependency list is available in the Cargo.toml files (I'll probably make a list of them sometime)

## **Installation:**
- **it's all still a work in progress**