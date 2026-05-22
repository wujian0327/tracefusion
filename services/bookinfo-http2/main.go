package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

const listenAddr = ":9080"

var (
	bookCount          = envInt("BOOK_COUNT", 100)
	detailsHostname    = envString("DETAILS_HOSTNAME", "details")
	detailsServicePort = envString("DETAILS_SERVICE_PORT", "9080")
	reviewsHostname    = envString("REVIEWS_HOSTNAME", "reviews")
	reviewsServicePort = envString("REVIEWS_SERVICE_PORT", "9080")
	ratingsHostname    = envString("RATINGS_HOSTNAME", "ratings")
	ratingsServicePort = envString("RATINGS_SERVICE_PORT", "9080")
	httpClient         = newH2CClient()
)

type Details struct {
	ID        int    `json:"id"`
	Author    string `json:"author"`
	Genre     string `json:"genre"`
	ISBN10    string `json:"ISBN-10"`
	ISBN13    string `json:"ISBN-13"`
	Language  string `json:"language"`
	Pages     int    `json:"pages"`
	Publisher string `json:"publisher"`
	Type      string `json:"type"`
	Year      int    `json:"year"`
}

type Ratings struct {
	ID      int            `json:"id"`
	Ratings map[string]int `json:"ratings"`
	Source  string         `json:"source"`
}

type Review struct {
	Reviewer string `json:"reviewer"`
	Text     string `json:"text"`
	Rating   int    `json:"rating"`
}

type Reviews struct {
	ID      int      `json:"id"`
	Reviews []Review `json:"reviews"`
	Ratings Ratings  `json:"ratings"`
}

type ProductPage struct {
	ID      int     `json:"id"`
	Title   string  `json:"title"`
	Details Details `json:"details"`
	Reviews Reviews `json:"reviews"`
	Service string  `json:"service"`
}

func main() {
	role := envString("SERVICE_ROLE", "productpage")
	mux := http.NewServeMux()
	mux.HandleFunc("/health", jsonHandler(func(_ *http.Request) any {
		return map[string]string{"status": role + " is healthy", "protocol": "h2c"}
	}))

	switch role {
	case "details":
		mux.HandleFunc("/details/", jsonHandler(detailsHandler))
	case "ratings":
		mux.HandleFunc("/ratings/", jsonHandler(ratingsHandler))
	case "reviews":
		mux.HandleFunc("/reviews/", jsonHandler(reviewsHandler))
	case "productpage":
		mux.HandleFunc("/", jsonHandler(productpageHandler))
		mux.HandleFunc("/productpage", jsonHandler(productpageHandler))
	default:
		log.Fatalf("unknown SERVICE_ROLE=%q", role)
	}

	server := &http.Server{
		Addr:              listenAddr,
		Handler:           h2c.NewHandler(mux, &http2.Server{}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("starting %s h2c service on %s", role, listenAddr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func productpageHandler(r *http.Request) any {
	bookID := selectedBookID(r)
	detailsURL := fmt.Sprintf("http://%s:%s/details/%d", detailsHostname, detailsServicePort, bookID)
	reviewsURL := fmt.Sprintf("http://%s:%s/reviews/%d", reviewsHostname, reviewsServicePort, bookID)

	var details Details
	mustGetJSON(r.Context(), detailsURL, r, &details)

	var reviews Reviews
	mustGetJSON(r.Context(), reviewsURL, r, &reviews)

	return ProductPage{
		ID:      bookID,
		Title:   fmt.Sprintf("HTTP/2 Book %03d", bookID),
		Details: details,
		Reviews: reviews,
		Service: "bookinfo-http2-productpage",
	}
}

func detailsHandler(r *http.Request) any {
	bookID := pathID(r, "/details/")
	genres := []string{"distributed systems", "database internals", "observability", "performance engineering", "networking"}
	return Details{
		ID:        bookID,
		Author:    fmt.Sprintf("Author %02d", bookID),
		Genre:     genres[bookID%len(genres)],
		ISBN10:    fmt.Sprintf("1234567%03d", bookID),
		ISBN13:    fmt.Sprintf("978-1-4028-%04d-%d", bookID, bookID%10),
		Language:  "English",
		Pages:     120 + bookID*7,
		Publisher: fmt.Sprintf("Publisher%02d", bookID%9),
		Type:      "paperback",
		Year:      2000 + bookID%25,
	}
}

func reviewsHandler(r *http.Request) any {
	bookID := pathID(r, "/reviews/")
	ratingsURL := fmt.Sprintf("http://%s:%s/ratings/%d", ratingsHostname, ratingsServicePort, bookID)
	var ratings Ratings
	mustGetJSON(r.Context(), ratingsURL, r, &ratings)
	return Reviews{
		ID: bookID,
		Reviews: []Review{
			{
				Reviewer: "Reviewer1",
				Text:     fmt.Sprintf("HTTP/2 review one for book %d", bookID),
				Rating:   ratings.Ratings["Reviewer1"],
			},
			{
				Reviewer: "Reviewer2",
				Text:     fmt.Sprintf("HTTP/2 review two for book %d", bookID),
				Rating:   ratings.Ratings["Reviewer2"],
			},
		},
		Ratings: ratings,
	}
}

func ratingsHandler(r *http.Request) any {
	bookID := pathID(r, "/ratings/")
	source := rand.New(rand.NewSource(int64(bookID) + 17))
	return Ratings{
		ID: bookID,
		Ratings: map[string]int{
			"Reviewer1": 1 + source.Intn(5),
			"Reviewer2": 1 + source.Intn(5),
		},
		Source: "go-h2c-ratings",
	}
}

func jsonHandler(fn func(*http.Request) any) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Bookinfo-Protocol", "h2c")
		if err := json.NewEncoder(w).Encode(fn(r)); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func newH2CClient() *http.Client {
	return &http.Client{
		Transport: &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				dialer := &net.Dialer{Timeout: 3 * time.Second}
				return dialer.DialContext(ctx, network, addr)
			},
		},
		Timeout: 5 * time.Second,
	}
}

func mustGetJSON(ctx context.Context, url string, inbound *http.Request, out any) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		panic(err)
	}
	for _, name := range []string{"x-mark", "x-request-id", "x-trace-id", "x-b3-traceid", "x-b3-spanid", "traceparent", "tracestate", "user-agent"} {
		if value := inbound.Header.Get(name); value != "" {
			req.Header.Set(name, value)
		}
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		panic(fmt.Sprintf("unexpected status from %s: %s", url, resp.Status))
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		panic(err)
	}
}

func selectedBookID(r *http.Request) int {
	rawID := r.URL.Query().Get("id")
	id, err := strconv.Atoi(rawID)
	if err != nil {
		return 0
	}
	return positiveMod(id, bookCount)
}

func pathID(r *http.Request, prefix string) int {
	rawID := strings.TrimPrefix(r.URL.Path, prefix)
	id, err := strconv.Atoi(rawID)
	if err != nil {
		return 0
	}
	return positiveMod(id, bookCount)
}

func positiveMod(value int, mod int) int {
	if mod <= 0 {
		return value
	}
	value %= mod
	if value < 0 {
		value += mod
	}
	return value
}

func envString(name string, fallback string) string {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	return value
}

func envInt(name string, fallback int) int {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return value
}
