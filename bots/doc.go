/*
Package bots implements the CONIKS third-party account verification
protocol, which ensures that only legitimate users of third-party
communication services (e.g. Twitter, IRC) are able to register and
update CONIKS key directory entries.

At a high-level, a proxy server registers (or updates) a username-to-key
mapping in the CONIKS key directory on behalf of the corresponding
third-party account and relays these requests to the CONIKS server.

Overview

CONIKS clients and a trusted proxy server participate in the third-party
account verification protocol. The CONIKS client generates a new key pair
for each username the user creates. If this username corresponds to a
third-party account (e.g. a Twitter handle), the client will ask the user
to connect to her account using her credentials, and will attempt to
register the username and the public key with the CONIKS server.

The registration proxy is connected to reserved user account with the
same third-party service, allowing the CONIKS client to send messages
to the proxy using the service's communication system. Therefore, in
order to register a new username-to-key mapping, the client must send
the request to the proxy's reserved third-party account.

Privacy is a key feature of CONIKS, so the only piece of third-party
account information that the CONIKS client and proxy store (or even see?),
and send to the CONIKS server is the username.

Assumptions and Threat Model

We are most concerned with an attacker attempting to impersonate
a user of a third-party service (e.g. Twitter, IRC)
by registering a name-to-key mapping for this user with the CONIKS server.

Requiring that the legitimate user connect to her third-party account
using the correct credentials serves as a proof of ownership of
the account, and we assume that obtaining this user's credentials is a
sufficiently large burden to deter most adversaries from mounting the
impersonation attack.

By only accepting registration requests via a reserved account using
the third-party communication, the proxy trusts that any requests sent
by CONIKS clients to its account originated from uncompromised
third-party accounts.

To further restrict the allowable sources of registration requests, the
CONIKS server only accepts incoming registration requests originating
from the account proxy, and trusts that the proxy has
performed the necessary third-party account verifications.

Third-Party Account Verification Protocol

1. The user adds her username to the CONIKS client, and connects to the corresponding account with the third-party service.

2. The client sends a registration request containing the generate public key to the proxy's account using the service's communication protocol using the added username.

3. The proxy verifies that the sender of the request is a legitimate account, and sends a registration request to the CONIKS server.

4. Once the server receives and processes the request, it sends its response (either success or an error) to the proxy, which relays the response back to the CONIKS client.

Supported Third-Party Services

The current implementation supports third-party account verification of
Twitter handles. The registration bot must receive a CONIKS registration
request via a Twitter direct message (DM) from a legitimate Twitter account in order to send a registration request to the CONIKS server.

*/
package bots
