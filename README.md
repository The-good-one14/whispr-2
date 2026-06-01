# **Whispr**, the app that doesn't need your driver's license to work
### Whispr v2 is the successor of Whispr-chat, a web based chat app in python/html/css/js
### **The app is currently in alpha, and cannot be used at this time.**
---
### **Features:**
- **Secure asymmetric key encryption and signing:** The app uses ed25519 and x25519 for signing and encrypting messages respectively.
- **Forward secrecy:** a new temporary keypair and Nonce (number used once) is used for every message, effectively keeping message history private even after a leak.
- **Blind Server structure:** The architecture is designed that the server (even if rebuilt with malicious intent by say, a hacker) does *not* have the ability to read messages.
- **Multible platform support:** (Eventually) the app will be avaible as TUI, website, and GUI app.
- **Direct messaging and group chats:** Group rooms will have a structure similar to Discord, where anyone can access it with the right name and key. Rooms are also able to be public, meaning no password/key is needed and anyone can access it.
- **P2P:** In post-mvp, there will be the ability to communicate without a server, keeping all the anonymity and security but with zero downtime, at the cost of simplicity.
- **save & private chat history:** Chat history is saved *locally*, meaning no one can access it except you.
- **No Identification needed:** setting up an account requires absolutely zero personal info, an account is completely based and dependent on an ed25519 keypair instead of a traditional username & password
#### **Disclaimer:** some of these features are post-mvp and may not be implemented yet.

---
### **Tech stack**:
- 100% rust
- cryptography uses ed25519-dalek and x25519-dalek together with chacha20poly1305 and hkdf
- serde and postcard for serialization
- full dependency list is available in the Cargo.toml files (I'll probably make a list of them sometime)

---
### **Installation:**
- **Not available yett, I'm working on it**
-
--
### **AI usage disclaimer:** 
#### what AI *is not* used for:
- Writing of code
#### what AI *is* used for:
- Brainstorming
- Planning

**All code is completely under human control, down to the last letter. It would be a HUGE security issue if ai would autonomously write code designed to be private and secure.**
