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
key directories. This this less of an issue for secure communication
services which run CONIKS key directory servers themselves, but
third-party secure communication services need additional assurance
that their users own the first-party accounts they register and use.

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

Identity Providers: Most communication services require each user to 
register an account to participate, which can be addressed with the
user-chosen username. Identity providers maintain disjoint
namespaces for the usernames in their service; in other words,
two separate persons may each register the same name with two different
services, thereby creating two separate (likely unrelated) online 
identities.

bots assumes that identity providers do not run CONIKS key directory 
servers themselves and may even be unaware of a third-party CONIKS 
server for their users. 
Thus, bots assumes that third-party secure communication services 
providing security on behalf of identity providers run a CONIKS key
directory. This also means
that the third-party service must handle registering the identities
with the CONIKS key server on behalf of the identity provider.

Users: In order to use CONIKS-backed secure communication services that 
do not provide new identities, users must authorize the service
to connect to their first-party account.
bots leverages this authorization in its account verification protocol,
and trusts that the service's clients use a secure authorization procotol
such as OAuth.

CONIKS clients: Users run the third-party secure communication client 
software with an integrated CONIKS client. The CONIKS client software 
stores a for each of the user's registered 
first-party accounts. Depending on the secure communication service,
the key pairs may be generated by the communication
client or the CONIKS client.

Since users must authorize the third-party communication client to connect 
to their first-party accounts, bots assumes that this authorization
extends to the CONIKS client.
Much like the third-party communication services, bots assumes that 
obtaining a user's credentials needed for the authorization is a 
sufficiently large burden to deter most adversaries from attempting 
an impersonation attack.

Account proxies: The main component of bots are trusted proxy
servers, each of which connect to a reserved account with a designated
identity provider using an authorization protocol such as OAuth.
This allows CONIKS clients and the proxies to communicate directly using an
identity provider's communication protocol.

A proxy only accepts and relays CONIKS registration requests for accounts
with its designated identity provider, and the requests must be sent by
an authorized CONIKS client via the provider's communication protocol 
to the proxy's reserved account. As a result, a proxy trusts that any 
requests sent by CONIKS clients to its account originated from 
uncompromised first-party accounts.

CONIKS servers: bots proxies relay valiated CONIKS registration requests
to a designated CONIKS server. bots assumes that the CONIKS key directory 
server and proxies are both run by the third-party secure communication 
service, which may run the server and proxies as separate
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

Account Verification Protocol

1. The user registers her first-party account with her third-party 
communication client, thereby authorizing the client and the integrated 
CONIKS client to connect to her first-party account.

2. The CONIKS client generates a key pair, or obtains the key pair generated
by the secure communication client, for the new user account
and stores the public and private keys locally.

3. On behalf of the connected account, the CONIKS client sends a registration
request
    req = (username, opaque public key data blob)
to the designated bots account proxy using the identity provider's 
communication protocol.

4. The proxy receives the request at its reserved account via
the identity provider's protocol, and validates the sender ensuring
the request originated at an authorized CONIKS client.

5. The proxy sends the validated registration request to the
third-party CONIKS server.

6. Once the CONIKS server receives the request and authenticates the proxy,
it registers the username-to-public key mapping in its CONIKS key directory.
The server sends a cryptographic proof of registration to the proxy,
which relays the response back to the CONIKS client.

Supported Third-Party Services

The current implementation of bots supports account verification of 
Twitter accounts. The account proxy connects to its reserved Twitter
account using OAuth, and it only accepts CONIKS registration
requests received as Twitter direct messages sent from CONIKS clients
that have been authorized by a legitimate Twitter user.

Challenges and Limitations

bots faces many of the same challenges as identity providers running
*first-party* CONIKS servers. First, while bots provides strong security 
and privacy guarantees against modest attackers, bots' account
verification protocol is not robust against motivated,
resourceful attackers. These may still be able to obtain the necessary
credentials to authorize a malicious CONIKS client and impersonate a
target user. Additionally, much like CONIKS servers, bots proxies are 
designed to be agnostic to the secure communication service's encryption 
protocol and key format. Therefore, bots proxies (and CONIKS servers alike)
cannot verify explicitly the ownership of registered public keys.

One challenge specific to the third-party CONIKS server scenario
that bots faces is attribution for a spurious key.
In the first-party CONIKS server case, since the identity provider and
CONIKS server are run by the same entity, any spurious key registered in
the directory can be attributed to a malicious identity provider.
However, since bots proxies cannot generate any cryptographic proof of
the identity provider's participation in the registration protocol
without the provider's cooperation, clients do not have any 
evidence should the identity provider register
a spurious key for a target user. Conversely, third-party CONIKS servers 
are not able to detect such an attack by the identity provider
and cannot defend themselves against it due to the lack of cryptographic
evidence. A solution to this problem would likely require identity provider
cooperation in the bots account verification protocol, which bots does not
currently attempt to obtain.

Resources

- CONIKS: http://coniks.org

- Connecting to Twitter using OAuth: https://dev.twitter.com/oauth

*/
package bots
