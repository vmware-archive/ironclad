# Ironclad: WAF on Kubernetes

This is a reference configuration for running a web application firewall (WAF) on Kubernetes.
It is a container build of [ModSecurity+Nginx][modsecurity-nginx] running the [ModSecurity Core Rule Set][modsecurity-crs] along with a Go helper.

The Ironclad container runs as a sidecar for your application.
It proxies inbound requests to your application over localhost within confines of a single Kubernetes Pod.

The Go helper helps the process integrate more nicely in a Kubernetes environment:

- Supports live-reload of rule configuration from a ConfigMap.

- Has useful [liveness and readiness hooks][probes] to enable safe deploys.

- Emits JSON-formatted logs.

- Emits [Prometheus][prometheus] metrics.

## Proof of Concept

This code is a work in progress and is meant as a simple proof of concept.
File an issue or talk to [@mattmoyer] if you have ideas or want to help.

## Configuration Format

```yaml
# If true, ModSecurity will not block requests it thinks are malicious.
detectionOnly: false

# The TCP port on which Nginx should listen for requests.
listenPort: 80

# The TCP port to which Nginx should forward requests.
# Your application should be configured to listen on 127.0.0.1:8080.
backendPort: 8080

# Emit logs in JSON format (default is a text-based format)
logFormat: json

# Log at INFO level (includes alerts).
logLevel: info

# Prepend zero or more rules to the ModSecurity Core Rule Set.
prependRules: []

# Append zero or more rules to the ModSecurity Core Rule Set.
appendRules:
 # For example, change the default "block" action to a redirect:
 - SecDefaultAction "phase:1,nolog,auditlog,redirect:https://bit.ly/2GtuuDZ"
 - SecDefaultAction "phase:2,nolog,auditlog,redirect:https://bit.ly/2GtuuDZ"
```

## Notes

This product includes GeoLite2 data created by MaxMind, available from [https://maxmind.com](https://www.maxmind.com/).

[@mattmoyer]: https://github.com/mattmoyer
[modsecurity]: https://github.com/SpiderLabs/ModSecurity
[modsecurity-nginx]: https://github.com/SpiderLabs/ModSecurity-nginx
[modsecurity-crs]: https://coreruleset.org/
[prometheus]: https://prometheus.io/
[probes]: https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/#container-probes