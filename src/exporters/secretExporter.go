package exporters

import (
	"github.com/joe-elliott/cert-exporter/src/metrics"
)

// SecretExporter exports PEM file certs
type SecretExporter struct {
}

// ExportMetrics exports the provided PEM file
func (c *SecretExporter) ExportMetrics(bytes []byte, keyName, secretName, secretNamespace, certPassword string) error {
	metricCollection, err := secondsToExpiryFromCertAsBytes(bytes, certPassword, nil, nil, nil) // No CN/Alias/Issuer specific filters for Secret certs
	if err != nil {
		return err
	}

	for _, metric := range metricCollection {
		metrics.SecretExpirySeconds.WithLabelValues(keyName, metric.issuer, metric.cn, secretName, secretNamespace).Set(metric.durationUntilExpiry)
		metrics.SecretNotAfterTimestamp.WithLabelValues(keyName, metric.issuer, metric.cn, secretName, secretNamespace).Set(metric.notAfter)
		metrics.SecretNotBeforeTimestamp.WithLabelValues(keyName, metric.issuer, metric.cn, secretName, secretNamespace).Set(metric.notBefore)
	}

	return nil
}

func (c *SecretExporter) ResetMetrics() {
	metrics.SecretExpirySeconds.Reset()
	metrics.SecretNotAfterTimestamp.Reset()
	metrics.SecretNotBeforeTimestamp.Reset()
}
