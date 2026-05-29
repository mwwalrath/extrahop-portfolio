# ExtraHop OSS Portfolio

Open source tools and detections built for the ExtraHop platform. Two custom triggers and two Python REST API tools, each addressing a real gap in native capability that I hit during customer engagements as a Solutions Architect at ExtraHop Networks.

The triggers fill gaps in platform detection coverage - timeroasting attempts against Domain Controllers, data-feed loss at the VLAN level. The Python tools automate operational work the UI does not cover at scale - bulk custom-device management across many appliances, and source IP scoping for Allow List rollouts.

## Projects

### [Custom Device Manager](./custom-device-manager)

Python CLI for bulk audit, create, patch, and delete of ExtraHop custom devices via the REST API. Standard-library only at runtime, with `--dry-run` previews, three patch modes (replace, append, remove), and automatic reconnection mid-run for long jobs across multiple appliances.

### [MS-SNTP Authentication Record Trigger](./ms-sntp-authentication-record-trigger)

ExtraHop trigger that parses the MS-SNTP authentication trailer from NTPv3 traffic and commits enriched records for [timeroasting](https://github.com/SecuraBV/Timeroast) detection. Dual-event coverage on `NTP_MESSAGE` and `UDP_PAYLOAD` catches both classified flows and the unanswered single-packet UDP that the platform may never classify on its own.

### [RevealX 360 Audit Log Source Aggregator](./revealx-360-audit-log-source-aggregator)

Python tool that pulls the RevealX 360 audit log via REST API and aggregates source IPs into /24 buckets for scoping a RevealX 360 Allow List. Separates legitimate traffic from the constant scanner noise on the public OAuth endpoint and flags addresses that are XFF-injected or NLB internal hops rather than real Allow List candidates.

### [VLAN Down Detector](./vlan-down-detector)

ExtraHop trigger that detects when active VLANs fall off the data feed. Three monitoring tiers (critical, standard, low-value) with independent thresholds and refire intervals. Discovers active VLANs from the REST API on a 5-minute cycle, observes traffic on 30-second metric cycles, and consolidates outage and recovery into a single detection card.

## License

BSD 2-Clause. See [LICENSE](LICENSE).

## Contact

- LinkedIn: [linkedin.com/in/mwwalrath-solutionsarchitect/](https://www.linkedin.com/in/mwwalrath-solutionsarchitect/)
- Email: [m.w.walrath@gmail.com](mailto:m.w.walrath@gmail.com)
