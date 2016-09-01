/*
Package bots implements an account verification
system for third-party CONIKS key directory servers.

bots ensures that only legitimate users of communication services 
(e.g. Twitter, IRC) are registered in a third-party CONIKS key directory.

Introduction

Many communication services today do not yet provide built-in solutions
for users wishing to secure their commnications using end-to-end encryption.
Security-conscious users, therefore, often use third-party secure 
communication services on top of their existing communication services.
As a result, these third-party communication services must also provide
encryption key management for their users.

CONIKS is a key management and verification system which ensures that 
the public keys maintained for users in CONIKS key directories remain 
consistent over time and across different vantage points in the system. 
But CONIKS only ensures the consistency of online identities, and makes 
no guarantees about the persons who own the usernames registered in the
key directories.

For third-party services running a CONIKS key directory, bots bridges 
this gap by providing a proxy-based mechanism to verify that the key
directory entries belong to the legitimate owners of the corresponding
first-party communication service accounts.
At a high-level, a bots proxy server verifies that
all username-to-key mappings to be registered in the CONIKS key directory
correspond to a legitimate first-party account.

System Model and Assumptions

bots' security model includes five main principals, and is most concerned
with an attacker attempting to impersonate a user of a communication service
(e.g. Twitter, IRC) by registering a name-to-key mapping for this user
with a third-party CONIKS server.

Identity Providers: Most communication services require users to register
new usernames to participate, thereby providing a service-specific online 
identity for each user. To do so, these services manage namespaces, which
are disjoint from other identity providers' namespaces; in other words,
two different persons may each register the same name with two different
services and use these services without conflict. 

bots assumes that identity providers do not run CONIKS servers themselves, 
but that third-party secure communication services providing security on 
behalf of identity providers run a CONIKS key directory. This also means
that the third-party service must handle registering first-party usernames
with the CONIKS key server on behalf of the identity provider.

Account proxies: The main component of bots are trusted proxy
servers, each of which connect to a reserved account with a designated
third-party service using an authorization protocol such as OAuth.
This allows CONIKS clients and the proxies to communicate directly using a
service's communication protocol.

A proxy only accepts and relays CONIKS registration requests for accounts
with its designated third-party service, and the requests must be sent by
an authorized CONIKS client via the service's protocol to the proxy's
reserved account. As a result, a proxy trusts that any requests sent
by CONIKS clients to its account originated from uncompromised
third-party accounts.

Users: For CONIKS-backed secure communication services that do not
provide first-party user accounts, users must authorize the service
to connect to their third-party account in order to use the service.
bots leverages this authorization in its account verification protocol,
and trusts that the service's clients use a secure authorization procotol
such as OAuth.

CONIKS clients: Users run the communication client software with
an integrated CONIKS client. The CONIKS client software generates and
stores a key pair for each of the user's registered accounts.
bots assumes that users authorize CONIKS clients to connect to their
third-party accounts as part of the communication client's authorization.
Much like these communication services, bots assumes that obtaining a user's
credentials needed for the authorization is a sufficiently large burden
to deter most adversaries from attempting an impersonation attack.

CONIKS servers: bots proxies relay verified CONIKS registration requests
to a designated CONIKS server. The server and proxies may run as separate
processes on the same machine, or on separate machines, depending on the
communication service's infrastructure. For authentication, bots proxies
can be configured to digitally sign all requests they relay, or to
establish a secure network connection with the server. The server then
only accepts incoming registration requests originating from authenticated
account proxies.

Privacy

bots seeks to provide the same strong privacy guarantees as CONIKS.
CONIKS clients using bots only store the generated key pairs and
registered third-party usernames. bots only sends the username and
the public key as an opaque data blob to the corresponding account proxy.
bots also ensures that the clients do not gain access to any other
third-party account information.

The account proxies only have access to a user's username with their
designated service and the received public key, and this is
the only user information they send to the server.
Proxies cannot access any other account information.

Third-Party Account Verification Protocol

1. The user registers her third-party account with her communication
client, thereby authorizing the client and the integrated CONIKS client
to connect to her third-party account.

2. The CONIKS client generates a key pair for the new user account
and stores the public and private key locally.

3. On behalf of the connected account, the client sends a registration
request
    req = (username, opaque public key data blob)
to the designated account proxy using the service's communication
protocol.

4. The proxy receives the request at its reserved account via
the service's protocol, and verifies that the sender
is an authorized client.

5. The proxy sends the verified registration request to its designated
CONIKS server.

6. Once the CONIKS server receives the request and authenticates the proxy,
it registers the username-to-public key mapping in its CONIKS directory.
The server sends a cryptographic proof of registration to the proxy,
which relays the response back to the CONIKS client.

Supported Third-Party Services

The current implementation supports third-party account verification of
Twitter accounts. The account proxy connects to its reserved Twitter
account using OAuth, and it only accepts CONIKS registration
requests received as Twitter direct messages sent from CONIKS clients
that have been authorized by a legitimate Twitter account.

Challenges and Limitations

While bots provides strong security and privacy guarantees against
modest attackers, our protocol is not robust against motivated,
resourceful attackers; these may be able to obtain the necessary
credentials to authorize a malicious CONIKS client and impersonate a
target user. Additionally, we avoid exposing the user's public key to
the registration proxy, which favors user privacy, but this also limits
the proxy's ability to verify explicitly the ownership of this public key
via a digital signature of the message using the corresponding private key.

Resources

- CONIKS: http://coniks.org

- Connecting to Twitter using OAuth: https://dev.twitter.com/oauth

*/
package bots
