package search

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/delimitrou/DeathStarBench/tree/master/hotelReservation/registry"
	geo "github.com/delimitrou/DeathStarBench/tree/master/hotelReservation/services/geo/proto"
	rate "github.com/delimitrou/DeathStarBench/tree/master/hotelReservation/services/rate/proto"
	pb "github.com/delimitrou/DeathStarBench/tree/master/hotelReservation/services/search/proto"
	"github.com/delimitrou/DeathStarBench/tree/master/hotelReservation/tracing"
	"github.com/google/uuid"
	opentracing "github.com/opentracing/opentracing-go"
	"github.com/rs/zerolog/log"
	context "golang.org/x/net/context"
)

const name = "srv-search"

type xMarkContextKey struct{}

func contextWithXMark(ctx context.Context, r *http.Request) context.Context {
	if mark := r.Header.Get("X-Mark"); mark != "" {
		return context.WithValue(ctx, xMarkContextKey{}, mark)
	}
	return ctx
}

func xMarkFromContext(ctx context.Context) string {
	mark, _ := ctx.Value(xMarkContextKey{}).(string)
	return mark
}

// Server implments the search service
type Server struct {
	pb.UnimplementedSearchServer

	uuid string

	Tracer     opentracing.Tracer
	Port       int
	IpAddr     string
	ConsulAddr string
	KnativeDns string
	Registry   *registry.Client
}

// Run starts the server
func (s *Server) Run() error {
	if s.Port == 0 {
		return fmt.Errorf("server port must be set")
	}

	s.uuid = uuid.New().String()

	err := s.Registry.Register(name, s.uuid, s.IpAddr, s.Port)
	if err != nil {
		return fmt.Errorf("failed register: %v", err)
	}
	log.Info().Msg("Successfully registered in consul")

	mux := tracing.NewServeMux(s.Tracer)
	mux.Handle("/nearby", http.HandlerFunc(s.nearbyHTTPHandler))
	return http.ListenAndServe(fmt.Sprintf(":%d", s.Port), mux)
}

// Shutdown cleans up any processes
func (s *Server) Shutdown() {
	s.Registry.Deregister(s.uuid)
}

// Nearby returns ids of nearby hotels ordered by ranking algo
func (s *Server) Nearby(ctx context.Context, req *pb.NearbyRequest) (*pb.SearchResult, error) {
	// find nearby hotels
	log.Trace().Msg("in Search Nearby")

	log.Trace().Msgf("nearby lat = %f", req.Lat)
	log.Trace().Msgf("nearby lon = %f", req.Lon)

	nearby := new(geo.Result)
	err := s.postJSON(ctx, "http://geo:8083/nearby", &geo.Request{
		Lat: req.Lat,
		Lon: req.Lon,
	}, nearby)
	if err != nil {
		return nil, err
	}

	for _, hid := range nearby.HotelIds {
		log.Trace().Msgf("get Nearby hotelId = %s", hid)
	}

	// find rates for hotels
	rates := new(rate.Result)
	err = s.postJSON(ctx, "http://rate:8084/rates", &rate.Request{
		HotelIds: nearby.HotelIds,
		InDate:   req.InDate,
		OutDate:  req.OutDate,
	}, rates)
	if err != nil {
		return nil, err
	}

	// TODO(hw): add simple ranking algo to order hotel ids:
	// * geo distance
	// * price (best discount?)
	// * reviews

	// build the response
	res := new(pb.SearchResult)
	for _, ratePlan := range rates.RatePlans {
		log.Trace().Msgf("get RatePlan HotelId = %s, Code = %s", ratePlan.HotelId, ratePlan.Code)
		res.HotelIds = append(res.HotelIds, ratePlan.HotelId)
	}
	return res, nil
}

func (s *Server) nearbyHTTPHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req pb.NearbyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	res, err := s.Nearby(contextWithXMark(r.Context(), r), &req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

func (s *Server) postJSON(ctx context.Context, url string, in interface{}, out interface{}) error {
	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(in); err != nil {
		return err
	}

	clientSpan, clientCtx := opentracing.StartSpanFromContextWithTracer(
		ctx,
		s.Tracer,
		"HTTP POST "+url,
	)
	clientSpan.SetTag("span.kind", "client")
	defer clientSpan.Finish()

	req, err := http.NewRequestWithContext(clientCtx, http.MethodPost, url, &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if mark := xMarkFromContext(ctx); mark != "" {
		req.Header.Set("X-Mark", mark)
	}
	_ = s.Tracer.Inject(clientSpan.Context(), opentracing.HTTPHeaders, opentracing.HTTPHeadersCarrier(req.Header))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s returned %s: %s", url, resp.Status, string(msg))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
