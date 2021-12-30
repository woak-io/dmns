# DMNS: Domain Mname Server

A *simple* Mnemonic DNS server for easily remembering IPv4 Addresses inpired by [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) (in-fact, it uses the same wordlist).

127.0.0.1 -> word-word-word

word-word-word -> 10.0.0.1

sha256(word-word-word) -> 192.168.0.1



# Scope

- IPv4 to 3-word nmemonic

- 3-word nmemonic to IPv4

# Future Scope

- 11-word + number (2^8) nmemonic to IPv6

- IPv6 to 11-word + number (2^8) nmemonic