/*
Package client provides a library for all client-side CONIKS operations.

Introduction

One crucial component of the CONIKS key management system are the clients
verifying the cryptographic proofs returned by the CONIKS server as part of
the registration, lookup and monitoring protocols. client implements the
operations performed by CONIKS clients during these protocols. This document
outlines each of these protocols from a client perspective.

For the server-side specification of the CONIKS protocols, see
https://godoc.org/github.com/coniks-sys/coniks-go/server

Registration

Prerequisites: This protocol requires that the client pin both the
server's public signing key for verifying signed tree roots (STRs) and
the server's initial private index verification key (i.e. the public
VRF key). We assume a separate PKI exists to manage the server's keys.

Use of a CONIKS account verification bot is optional (see
https://godoc.org/github.com/coniks-sys/coniks-go/bots for details).
If the corresponding CONIKS key server requires that all registered names
be validated by a CONIKS registration bot, the client also pins the
registration bot that proxies all of its registration requests.
Additionally, as the network of CONIKS auditors is currently very small,
the client also maintains a list of pinned auditors. In a future release,
we plan to introduce an automatic update mechanism for the auditors list
while the development of a more scalable auditor discovery mechanism
is underway.

Protocol:
- The user enters her username into the CONIKS client GUI prompt.

- The client generates a new public-private key pair for this username,
and stores the keys in secure? local storage on the device.

- The client sends a registration request
        reg_req = (username, key)
to the server, or to the account validation bot, if used. See
https://godoc.org/github.com/coniks-sys/coniks-go/bots for the
CONIKS account validation protocol specification.

- If the registration request is accepted*, the server returns a
registration proof.
More specifically, the server returns a proof of absence:
        reg_pf = (auth_path, str)
If the server uses the temporary binding protocol extension, reg_pf will
also include a temporary binding (TB). See
https://godoc.org/github.com/coniks-sys/coniks-go/protocol/extensions/tb
for the temporary binding protocol extension specification.

- The client audits the received STR including a hash chain check.
See https://godoc.org/github.com/coniks-sys/coniks-auditor for the
auditing protocol specification. *Note: Auditing is not implemented yet.*

- Assuming the audit passes, the client proceeds to verify the TB, if
included: it verifies the server's signature on th TB and checks that
they public key in the TB matches the public key it sent to the proxy
in reg_req.

- Next, the client verifies that auth_path is a proof of absence by
checking that its private index is invalid for the username, and its
commitment is invalid for the public key it registered in reg_req.
The client then recomputes the server's directory root using auth_path,
and verifies that str includes the recomputed root in its signature.

- If the registration proof is invalid, the client notifies the user. The
Developing the reporting mechanism is planned for a future release.

* The registration request may be denied for one of the following reasons:
(1) The client attempts to register a name that already exists in the
CONIKS key directory (ErrorNameExisted); the server returns a
privacy-preserving proof of inclusion in its response. (2) The server
encounters an internal error when attempting to register the name
(ErrorDirectory).

Assumptions and Possible Attacks: The client accepts the STR in the
registration proof and assumes that the server has presented it with a
legitimate history with this initial STR (i.e. Tofu).
The main downside to the Tofu approach is that this does
allow a malicious server to place the client
on a forked branch of its history. However, by auditing the initial STR,
the client can detect this attack. Alternatively, the client could verify
the server's entire prior history to ensure that the server has not attempted
to equivocate about its initial STR. This approach would be more secure,
but has performance penalties. For now, we believe auditing will mitigate
this attack, but the need for a full prior history check upon registration
remains under discussion.

As mentinoed above, for performance reasons, the client does not check
the server's prior hisotry upon registering a new name. This enables
a malicious server to remove a legitimate username from the directory
and allow another user to re-register the name as the registering
client would not discover the prior existence of the name.
The server is then able to deny service to the original user by allowing
another user to re-register the name and use the name. In the worst case,
the server is complicit in a malicious user's attempt to assume the
identity of the legitimate user. However, if the server has created a
fork in its history to equivocate and attempt to conceal this attack,
the client of the original owner of the stolen username will detect
this attack via auditing and monitoring, and the registering client
will detect this attack during the auditing step of the registration
protocol.

Not checking the server's prior history during the registration protocol
also allows a malicious server to register a username, and remove
this name from the directory when a legitimate user registers the same
name to allow for the registration request to succeed. Assuming the server
has created a fork in its history at the point of the legitimate
registration, it can attempt to equivocate about the name. However, the
registering client can detect this
attack during the auditing step of the registration protocol.

What these attacks have in common is that they take advantage
of the fact that the registration protocol does not require the client
to verify the server's prior history allowing an illegitimate
re-registration of a username.  As a countermeasure, CONIKS does not
currently allow re-registration of retired usernames,
i.e. the user has deactivated and forfeit her account thereby making her
username available for use by another user. The design decision is
necessary since an attacker who is aware of the retired status of a victim's
username may re-register this user's name in order
to assume the victim's identity and impersonate her. Checking the server's
prior history is an insufficient countermeasure to this attack as
the intention of the new registrant cannot be verified by the client.

Other attacks related to registration include name-squatting
(i.e. registering large numbers of usernames in order
to sell the usage rights to interested users for a fee) and social
engineering attacks in which an attacker registers a victim user's
username in another service in order to trick the contacts of the victim
user into thinking that they are communicating with the legitimate user
via a CONIKS-backed communication service.

In general, the CONIKS
registration protocol cannot prevent an attacker
from registering a name before a legitimate user does, so there is a chance
that an attacker may be able to impersonate a legitimate user. This risk
is slightly mitigated by the fact that usernames in CONIKS diretories
are unique, so the legitimate user can simply register a different
username much like she would had aother legitimate user claimed her
preferred username first. While preventing name-squatting
and social engineering is beyond the scope of CONIKS, it may
be possible to reduce the avenues for a priori-registration by an
attacker in the case when the attacker is an identity provider who
manages its users keys in a third-party CONIKS server. We have not
developed a mechanism to prevent this scenario, but we suspect that
we may be able to leverage the intiial communication between
the identity provider and its CONIKS server during registration to
bind the identity provider to any registration originating from its
accounts.

*/
package client
