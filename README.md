# IPShield

A tiny Go service that provides a DNS server that checks IP addresses against the Firehol level 1 list, with responses indicating whether an IP is suspicious or not.

The DNS-based approach offers excellent performance in terms of latency. DNS queries are typically very fast, and the responses can be cached by clients and intermediate DNS servers, further reducing latency for repeated checks. This makes it an ideal solution for applications requiring quick and efficient IP reputation lookups.

## Features

- Automatic downloading and parsing of the Firehol level 1 list
- Periodic updates of the blocklist every 6 hours
- DNS responses cached for 1 hour

### Responses

- `SAFE` for safe IPs
- `DATACENTER` if the IP is from a known data center
- `SUSPICIOUS` for malicious IPs

## Try it out

```
dig <ip-addr> @localhost +short
```
