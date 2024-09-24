# IPShield

A tiny Go service that provides a DNS server that checks IP addresses against the Firehol level 1 list, known data center IPs, Tor exit nodes and other publicly available lists, with responses indicating whether an IP is suspicious or not.

The DNS-based approach offers excellent performance in terms of latency. DNS queries are typically very fast, and the responses can be cached by clients and intermediate DNS servers, further reducing latency for repeated checks. This makes it an ideal solution for applications requiring quick and efficient IP reputation lookups.

To install it on a any VM, run `curl -fsSL https://dub.sh/ipshield | bash`, you can set this up as a service. I'll add more docs soon.

## Features

- Automatic downloading and parsing of the Firehol level 1 list
- Periodic updates of the blocklist every 6 hours
- DNS responses cached for 1 hour

### Responses

- `SAFE` for safe IPs
- `DATACENTER` if the IP is from a known data center
- `SUSPICIOUS` for malicious IPs
- `TOR_EXIT` for Tor exit nodes

### Try it out

```
dig <ip-addr> @ipshield.dev TXT +short
```

## Security Considerations

You should probably use it within a private network if you really want to use it in production. Since the requests happen over DNS, it is not encrypted.

I could implement Transaction Signatures (TSIG) for secure DNS server communication when I get some time, if you're interested feel free to open a PR :)

## Why?

Just for fun, I have been trying Go for a while, and wanted to build a tiny service for bot protection for my side project [Picoletter](https://picoletter.com).

## Credits

- [jhassine/server-ip-addresses](https://github.com/jhassine/server-ip-addresses) for maintaining the datacenter IPs used.
- The inspiration for the DNS-based approach came from a friends project [dns.toys](https://www.dns.toys/)
