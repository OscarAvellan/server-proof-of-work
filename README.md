# server-proof-of-work

Server-based proof-of-work solver for the Hashcash mining algorithm used in Bitcoin.

Implement the functions in the Simple Stratum Text Protocol (SSTP), which is used to format messages between clients and your server program.

1.1 Ping Message 'PING'.
Server replies with 'PONG'.

1.2 Pong Message 'PONG'.
Server replies with 'PONG'.

1.3 Okay Message 'OKAY'.
Server replies with 'OKAY'.

1.4 Error Message 'ERRO'.
Server replies, 'ERRO: explanation'.

1.5 Solution Message 'SOLN'.
SOLN difficulty:unit32 seed:BYTE[64] solution:uint64.
If it is a valid proof-of-work, server replies with 'OKAY'.
Otherwise, 'ERRO: explanation'.

To run it:
$ make.
$ ./server port_number
