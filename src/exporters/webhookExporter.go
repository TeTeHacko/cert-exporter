package exporters

import (
	"github.com/joe-elliott/cert-exporter/src/metrics"
)

// WebhookExporter exports PEM file certs
type WebhookExporter struct {
}

// ExportMetrics exports the provided PEM file
func (c *WebhookExporter) ExportMetrics(bytes []byte, typeName, webhookName, admissionReviewVersionName string) error {
	metricCollection, err := secondsToExpiryFromCertAsBytes(bytes, "", nil, nil, nil) // No CN/Alias/Issuer specific filters for Webhook certs
	if err != nil {
		return err
	}

	for _, metric := range metricCollection {
		metrics.WebhookExpirySeconds.WithLabelValues(typeName, metric.issuer, metric.cn, webhookName, admissionReviewVersionName).Set(metric.durationUntilExpiry)
		metrics.WebhookNotAfterTimestamp.WithLabelValues(typeName, metric.issuer, metric.cn, webhookName, admissionReviewVersionName).Set(metric.notAfter)
		metrics.WebhookNotBeforeTimestamp.WithLabelValues(typeName, metric.issuer, metric.cn, webhookName, admissionReviewVersionName).Set(metric.notBefore)
	}

	return nil
}

func (c *WebhookExporter) ResetMetrics() {
	metrics.WebhookExpirySeconds.Reset()
	metrics.WebhookNotAfterTimestamp.Reset()
	metrics.WebhookNotBeforeTimestamp.Reset()
}
