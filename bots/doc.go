/*
Package bots implements the CONIKS account verification
protocol for first-party identity providers.

Many communication services provide user identifiers for
their users (e.g. Twitter, XMPP servers),
but do not provide end-to-end encryption by default. Users
wishing to communicate securely often opt to use a third-party
end-to-end encrypted communication service, which allows them
to connect their first-party account.

bots provides such third-party secure communication services
that use CONIKS for key management with a mechanism for
verifying that the first-party usernames registered with the
CONIKS key directory are registered by the authorized user.
More specifically, the account verification protocol involves
a registration proxy that checks all registration requests
before registering the new username with the server.

Bots

This module provides an account verification bot interface that can
be used to implement a CONIKS registration proxy for any
first-party identity provider.

Twitter Bot

This module provides a registration proxy for Twitter accounts
that implements the CONIKS account verification Bot interface.

CONIKS Bot

This subpackage provides an executable reference implementation for a CONIKS
registration proxy for Twitter accounts.
*/
package bots
