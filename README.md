[![Go Reference](https://pkg.go.dev/badge/github.com/kangaroux/go-wow-srp6.svg)](https://pkg.go.dev/github.com/kangaroux/go-wow-srp6)

This library implements the SRP6 protocol used in World of Warcraft.

```
go get github.com/kangaroux/go-wow-srp6
```

Check out the [gomaggus](https://github.com/Kangaroux/gomaggus) authd server for a reference on how this library is used (sorry, but it's 2AM and I'm too tired to write up a full example, unlucky).

## SRP6 Overview

> The [Gtker guide](https://gtker.com/implementation-guide-for-the-world-of-warcraft-flavor-of-srp6/#srp6-overview) provides an approachable and comprehensive look at SRP6. This library is heavily based on this guide.

SRP6 is a protocol used to authenticate users over an insecure connection. The client and server do a series of handshakes to prove they both know the password. At the end of the exchange, both parties will have a shared session key.

Prior to login, the user registers an account. The server stores the username, salt, and [password verifier](https://pkg.go.dev/github.com/kangaroux/go-wow-srp6#PasswordVerifier).

At the login screen, after the user has entered their username and password, the handshaking begins:

1. Client sends the username (challenge).
2. Server responds with the salt, the server's public key, and some parameters (challenge reply).
   - [gomaggus](https://github.com/Kangaroux/gomaggus/blob/fb845ea23e35ba9186a61a0865460fefdb6e5aa4/authd/handler/loginchallenge.go#L80) generates a fake salt if the username doesn't exist to protect against data mining, though this isn't necessary.
3. Client computes a proof and sends it (proof).
4. Server computes the same proof and compares it.
   - Proofs match: auth success, the client/server now have a shared session key.
   - Proofs don't match: auth failed, the client is kicked.

The session key is primarily used by the realm server for encryption (`realmd` in gomaggus, `worldd` in most other implementations). When the client connects to the realm server, they must once again prove they know the session key.
