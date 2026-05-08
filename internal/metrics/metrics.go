package metrics

import (
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	CertsIssuedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "ca",
		Name:      "certs_issued_total",
		Help:      "Total number of certificates issued",
	}, []string{"cert_type"})

	CertsRevokedTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "ca",
		Name:      "certs_revoked_total",
		Help:      "Total number of certificates revoked",
	})

	CertsExpiringSoon = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "ca",
		Name:      "certs_expiring_soon",
		Help:      "Number of certificates expiring within 30 days",
	})

	OCSPQueriesTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "ca",
		Name:      "ocsp_queries_total",
		Help:      "Total number of OCSP queries",
	})

	CRLRequestsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "ca",
		Name:      "crl_requests_total",
		Help:      "Total number of CRL requests",
	})
)

func init() {
	prometheus.MustRegister(CertsIssuedTotal)
	prometheus.MustRegister(CertsRevokedTotal)
	prometheus.MustRegister(CertsExpiringSoon)
	prometheus.MustRegister(OCSPQueriesTotal)
	prometheus.MustRegister(CRLRequestsTotal)
}

// IncCertsIssued 增加证书签发计数
func IncCertsIssued(certType string) {
	CertsIssuedTotal.WithLabelValues(certType).Inc()
}

// IncCertsRevoked 增加证书吊销计数
func IncCertsRevoked() {
	CertsRevokedTotal.Inc()
}

// SetCertsExpiringSoon 设置即将过期证书数量
func SetCertsExpiringSoon(count float64) {
	CertsExpiringSoon.Set(count)
}

// IncOCSPQueries 增加OCSP查询计数
func IncOCSPQueries() {
	OCSPQueriesTotal.Inc()
}

// IncCRLRequests 增加CRL请求计数
func IncCRLRequests() {
	CRLRequestsTotal.Inc()
}

// MetricsHandler Prometheus metrics HTTP handler
func MetricsHandler() gin.HandlerFunc {
	h := promhttp.Handler()
	return func(c *gin.Context) {
		h.ServeHTTP(c.Writer, c.Request)
	}
}
