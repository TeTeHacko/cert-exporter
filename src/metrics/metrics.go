package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	versioncollector "github.com/prometheus/client_golang/prometheus/collectors/version"
)

const (
	namespace = "cert_exporter"
)

// serialLabelEnabled is set by Init. When true, certificate metric families
// include a serial label so multi-PEM bundles with the same cn/issuer
// do not collapse into one Prometheus series.
var serialLabelEnabled bool

// SerialLabelEnabled reports whether certificate metrics include serial.
func SerialLabelEnabled() bool {
	return serialLabelEnabled
}

// AppendSerial appends serial to label values when the serial label is enabled.
func AppendSerial(labelValues []string, serial string) []string {
	if serialLabelEnabled {
		return append(labelValues, serial)
	}
	return labelValues
}

var (
	// ErrorTotal is a prometheus counter that indicates the total number of unexpected errors encountered by the application
	ErrorTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "error_total",
			Help:      "Cert Exporter Errors",
		},
	)

	// Discovered is a prometheus gauge for the number of files matched by
	// include/exclude globs across all file-based checkers (certs, kubeconfigs).
	// Concurrent checkers adjust it by delta rather than overwriting.
	Discovered = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "discovered",
			Help:      "Cert Exporter Discovered Certificates",
		},
	)

	// Certificate metric vectors are constructed in Init so the label set can
	// optionally include serial without a forced breaking change.
	CertExpirySeconds             *prometheus.GaugeVec
	CertNotAfterTimestamp         *prometheus.GaugeVec
	CertNotBeforeTimestamp        *prometheus.GaugeVec
	KubeConfigExpirySeconds       *prometheus.GaugeVec
	KubeConfigNotAfterTimestamp   *prometheus.GaugeVec
	KubeConfigNotBeforeTimestamp  *prometheus.GaugeVec
	SecretExpirySeconds           *prometheus.GaugeVec
	SecretNotAfterTimestamp       *prometheus.GaugeVec
	SecretNotBeforeTimestamp      *prometheus.GaugeVec
	CertRequestExpirySeconds      *prometheus.GaugeVec
	CertRequestNotAfterTimestamp  *prometheus.GaugeVec
	CertRequestNotBeforeTimestamp *prometheus.GaugeVec
	AwsCertExpirySeconds          *prometheus.GaugeVec
	ConfigMapExpirySeconds        *prometheus.GaugeVec
	ConfigMapNotAfterTimestamp    *prometheus.GaugeVec
	ConfigMapNotBeforeTimestamp   *prometheus.GaugeVec
	WebhookExpirySeconds          *prometheus.GaugeVec
	WebhookNotAfterTimestamp      *prometheus.GaugeVec
	WebhookNotBeforeTimestamp     *prometheus.GaugeVec

	// BuildInfo is a prometheus gauge that shows build information about the cert-exporter
	BuildInfo = versioncollector.NewCollector("cert_exporter")
)

func withSerial(labels []string) []string {
	if serialLabelEnabled {
		out := make([]string, len(labels)+1)
		copy(out, labels)
		out[len(labels)] = "serial"
		return out
	}
	return labels
}

// Init registers metrics. includeSerialLabel controls whether certificate
// gauges expose a serial label (off by default for Prometheus series
// compatibility; enable for multi-cert keys that share cn/issuer).
func Init(prometheusExporterMetricsDisabled bool, registry *prometheus.Registry, includeSerialLabel bool) {
	serialLabelEnabled = includeSerialLabel

	CertExpirySeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "cert_expires_in_seconds",
			Help:      "Number of seconds til the cert expires.",
		},
		withSerial([]string{"filename", "issuer", "cn", "nodename"}),
	)
	CertNotAfterTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "cert_not_after_timestamp",
			Help:      "Timestamp of when the certificate expires.",
		},
		withSerial([]string{"filename", "issuer", "cn", "nodename"}),
	)
	CertNotBeforeTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "cert_not_before_timestamp",
			Help:      "Timestamp of when the certificate becomes valid.",
		},
		withSerial([]string{"filename", "issuer", "cn", "nodename"}),
	)

	KubeConfigExpirySeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "kubeconfig_expires_in_seconds",
			Help:      "Number of seconds til the cert in the kubeconfig expires.",
		},
		withSerial([]string{"filename", "type", "cn", "issuer", "name", "nodename"}),
	)
	KubeConfigNotAfterTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "kubeconfig_not_after_timestamp",
			Help:      "Expiration timestamp for cert in the kubeconfig.",
		},
		withSerial([]string{"filename", "type", "cn", "issuer", "name", "nodename"}),
	)
	KubeConfigNotBeforeTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "kubeconfig_not_before_timestamp",
			Help:      "Activation timestamp for cert in the kubeconfig.",
		},
		withSerial([]string{"filename", "type", "cn", "issuer", "name", "nodename"}),
	)

	SecretExpirySeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "secret_expires_in_seconds",
			Help:      "Number of seconds til the cert in the secret expires.",
		},
		withSerial([]string{"key_name", "issuer", "cn", "secret_name", "secret_namespace"}),
	)
	SecretNotAfterTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "secret_not_after_timestamp",
			Help:      "Expiration timestamp for cert in the secret.",
		},
		withSerial([]string{"key_name", "issuer", "cn", "secret_name", "secret_namespace"}),
	)
	SecretNotBeforeTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "secret_not_before_timestamp",
			Help:      "Activation timestamp for cert in the secret.",
		},
		withSerial([]string{"key_name", "issuer", "cn", "secret_name", "secret_namespace"}),
	)

	CertRequestExpirySeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "certrequest_expires_in_seconds",
			Help:      "Number of seconds til the cert in the certrequest expires.",
		},
		withSerial([]string{"issuer", "cn", "cert_request", "certrequest_namespace"}),
	)
	CertRequestNotAfterTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "certrequest_not_after_timestamp",
			Help:      "Expiration timestamp for cert in the certrequest.",
		},
		withSerial([]string{"issuer", "cn", "cert_request", "certrequest_namespace"}),
	)
	CertRequestNotBeforeTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "certrequest_not_before_timestamp",
			Help:      "Activation timestamp for cert in the certrequest.",
		},
		withSerial([]string{"issuer", "cn", "cert_request", "certrequest_namespace"}),
	)

	AwsCertExpirySeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "cert_expires_in_seconds_aws",
			Help:      "Number of seconds til the cert expires.",
		},
		withSerial([]string{"secretName", "key", "file", "issuer", "cn"}),
	)

	ConfigMapExpirySeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "configmap_expires_in_seconds",
			Help:      "Number of seconds til the cert in the configmap expires.",
		},
		withSerial([]string{"key_name", "issuer", "cn", "configmap_name", "configmap_namespace"}),
	)
	ConfigMapNotAfterTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "configmap_not_after_timestamp",
			Help:      "Expiration timestamp for cert in the configmap.",
		},
		withSerial([]string{"key_name", "issuer", "cn", "configmap_name", "configmap_namespace"}),
	)
	ConfigMapNotBeforeTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "configmap_not_before_timestamp",
			Help:      "Activation timestamp for cert in the configmap.",
		},
		withSerial([]string{"key_name", "issuer", "cn", "configmap_name", "configmap_namespace"}),
	)

	WebhookExpirySeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "webhook_expires_in_seconds",
			Help:      "Number of seconds til the cert in the webhook expires.",
		},
		withSerial([]string{"type_name", "issuer", "cn", "webhook_name", "admission_review_version_name"}),
	)
	WebhookNotAfterTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "webhook_not_after_timestamp",
			Help:      "Expiration timestamp for cert in the webhook.",
		},
		withSerial([]string{"type_name", "issuer", "cn", "webhook_name", "admission_review_version_name"}),
	)
	WebhookNotBeforeTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "webhook_not_before_timestamp",
			Help:      "Activation timestamp for cert in the webhook.",
		},
		withSerial([]string{"type_name", "issuer", "cn", "webhook_name", "admission_review_version_name"}),
	)

	var registerer prometheus.Registerer

	if registry != nil {
		registerer = registry
	} else if prometheusExporterMetricsDisabled {
		emptyRegistry := prometheus.NewRegistry()
		prometheus.DefaultRegisterer = emptyRegistry
		prometheus.DefaultGatherer = emptyRegistry
		registerer = emptyRegistry
	} else {
		registerer = prometheus.DefaultRegisterer
	}

	registerer.MustRegister(Discovered)
	registerer.MustRegister(ErrorTotal)
	registerer.MustRegister(CertExpirySeconds)
	registerer.MustRegister(CertNotAfterTimestamp)
	registerer.MustRegister(CertNotBeforeTimestamp)
	registerer.MustRegister(KubeConfigExpirySeconds)
	registerer.MustRegister(KubeConfigNotAfterTimestamp)
	registerer.MustRegister(KubeConfigNotBeforeTimestamp)
	registerer.MustRegister(SecretExpirySeconds)
	registerer.MustRegister(SecretNotAfterTimestamp)
	registerer.MustRegister(SecretNotBeforeTimestamp)
	registerer.MustRegister(CertRequestExpirySeconds)
	registerer.MustRegister(CertRequestNotAfterTimestamp)
	registerer.MustRegister(CertRequestNotBeforeTimestamp)
	registerer.MustRegister(ConfigMapExpirySeconds)
	registerer.MustRegister(ConfigMapNotAfterTimestamp)
	registerer.MustRegister(ConfigMapNotBeforeTimestamp)
	registerer.MustRegister(WebhookExpirySeconds)
	registerer.MustRegister(WebhookNotAfterTimestamp)
	registerer.MustRegister(WebhookNotBeforeTimestamp)
	registerer.MustRegister(AwsCertExpirySeconds)
	registerer.MustRegister(BuildInfo)
}
