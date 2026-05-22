package tracing

import (
	opentracing "github.com/opentracing/opentracing-go"
	"github.com/rs/zerolog/log"
)

// Init returns a no-op tracer. Hotel HTTP/1.1 experiments use X-Mark headers
// as the ground-truth propagation signal, so they do not depend on Jaeger.
func Init(serviceName, host string) (opentracing.Tracer, error) {
	log.Info().Msgf("Using no-op tracer for %s; X-Mark propagation is enabled", serviceName)
	return opentracing.NoopTracer{}, nil
}
