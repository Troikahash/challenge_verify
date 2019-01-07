# Challenge Verify Tool 

This tool can be used to verify solutions for the cryptanalysis competition on
the Troika hash function. For further information on the competion see
<https://www.cyber-crypt.com/troika-challenge>. Note that this tool comes
without any warranty. 

# Building the tool

The tool requires the reference implementation which you can find at
<https://github.com/Troikahash/reference>. You can then simply compile
it with e.g.:

gcc -o verify verify.c troika.c

# How to use

The main of verify.c contains an example for verifying a preimage and an example
for verifying a collision challenge.

Note that the tool only allows to print tryte aligned input messages.
