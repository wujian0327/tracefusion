package tracefusion.bookinfojava;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

@RestController
public class BookinfoController {
    private static final String[] FORWARDED_HEADERS = {
            "x-request-id",
            "x-ot-span-context",
            "x-datadog-trace-id",
            "x-datadog-parent-id",
            "x-datadog-sampling-priority",
            "traceparent",
            "tracestate",
            "x-cloud-trace-context",
            "grpc-trace-bin",
            "x-b3-traceid",
            "x-b3-spanid",
            "x-b3-parentspanid",
            "x-b3-sampled",
            "x-b3-flags",
            "sw8",
            "end-user",
            "x-mark",
            "user-agent",
            "cookie",
            "authorization",
            "jwt"
    };

    private final RestTemplate restTemplate;
    private final String serviceRole;
    private final int bookCount;
    private final String detailsBaseUrl;
    private final String reviewsBaseUrl;
    private final String ratingsBaseUrl;
    private final boolean ratingsEnabled;
    private final String starColor;
    private final String podHostname;
    private final Map<Integer, Map<String, Object>> userAddedRatings = new HashMap<>();

    public BookinfoController(
            RestTemplate restTemplate,
            @Value("${SERVICE_ROLE:productpage}") String serviceRole,
            @Value("${BOOK_COUNT:100}") int bookCount,
            @Value("${DETAILS_HOSTNAME:details}") String detailsHostname,
            @Value("${DETAILS_SERVICE_PORT:9080}") int detailsPort,
            @Value("${REVIEWS_HOSTNAME:reviews}") String reviewsHostname,
            @Value("${REVIEWS_SERVICE_PORT:9080}") int reviewsPort,
            @Value("${RATINGS_HOSTNAME:ratings}") String ratingsHostname,
            @Value("${RATINGS_SERVICE_PORT:9080}") int ratingsPort,
            @Value("${ENABLE_RATINGS:true}") boolean ratingsEnabled,
            @Value("${STAR_COLOR:black}") String starColor
    ) {
        this.restTemplate = restTemplate;
        this.serviceRole = serviceRole;
        this.bookCount = Math.max(1, bookCount);
        this.detailsBaseUrl = "http://" + detailsHostname + ":" + detailsPort + "/details";
        this.reviewsBaseUrl = "http://" + reviewsHostname + ":" + reviewsPort + "/reviews";
        this.ratingsBaseUrl = "http://" + ratingsHostname + ":" + ratingsPort + "/ratings";
        this.ratingsEnabled = ratingsEnabled;
        this.starColor = starColor;
        this.podHostname = hostname();
    }

    @GetMapping("/health")
    public Map<String, String> health() {
        return Map.of("status", capitalize(serviceRole) + " is healthy");
    }

    @GetMapping("/productpage")
    public ResponseEntity<String> productPage(
            @RequestParam(name = "id", defaultValue = "0") String rawProductId,
            HttpServletRequest request
    ) {
        int productId = parseId(rawProductId);
        HttpHeaders headers = forwardHeaders(request);

        Map<String, Object> product = product(productId);
        Map<String, Object> details = getJson(detailsBaseUrl + "/" + productId, headers, fallback("details unavailable"));
        Map<String, Object> reviews = getReviewsWithRetry(productId, headers);

        String html = renderProductPage(product, details, reviews);
        return ResponseEntity.ok()
                .contentType(MediaType.TEXT_HTML)
                .body(html);
    }

    @GetMapping("/api/v1/products")
    public List<Map<String, Object>> products() {
        List<Map<String, Object>> products = new ArrayList<>();
        for (int i = 0; i < bookCount; i++) {
            products.add(product(i));
        }
        return products;
    }

    @GetMapping("/api/v1/products/{productId}")
    public ResponseEntity<Map<String, Object>> productRoute(
            @PathVariable String productId,
            HttpServletRequest request
    ) {
        HttpHeaders headers = forwardHeaders(request);
        return ResponseEntity.ok(getJson(detailsBaseUrl + "/" + parseId(productId), headers, fallback("details unavailable")));
    }

    @GetMapping("/api/v1/products/{productId}/reviews")
    public ResponseEntity<Map<String, Object>> reviewsRoute(
            @PathVariable String productId,
            HttpServletRequest request
    ) {
        return ResponseEntity.ok(getReviewsWithRetry(parseId(productId), forwardHeaders(request)));
    }

    @GetMapping("/api/v1/products/{productId}/ratings")
    public ResponseEntity<Map<String, Object>> ratingsRoute(
            @PathVariable String productId,
            HttpServletRequest request
    ) {
        HttpHeaders headers = forwardHeaders(request);
        return ResponseEntity.ok(getJson(ratingsBaseUrl + "/" + parseId(productId), headers, fallback("ratings unavailable")));
    }

    @GetMapping("/details/{productId}")
    public Map<String, Object> details(@PathVariable String productId) {
        int normalizedProductId = normalize(parseId(productId));
        List<String> genres = List.of(
                "distributed systems",
                "database internals",
                "observability",
                "networking",
                "cloud architecture",
                "debugging",
                "operating systems",
                "performance engineering"
        );

        Map<String, Object> details = new LinkedHashMap<>();
        details.put("id", normalizedProductId);
        details.put("author", String.format("Author %02d", normalizedProductId % 17));
        details.put("year", 2000 + (normalizedProductId % 24));
        details.put("type", "paperback");
        details.put("pages", 120 + ((normalizedProductId * 7) % 420));
        details.put("publisher", String.format("Publisher%02d", normalizedProductId % 9));
        details.put("language", "English");
        details.put("genre", genres.get(normalizedProductId % genres.size()));
        details.put("ISBN-10", String.format("%010d", 1234567890L + normalizedProductId));
        details.put("ISBN-13", String.format("978-1-4028-%04d-%d", normalizedProductId, normalizedProductId % 10));
        return details;
    }

    @GetMapping("/reviews/{productId}")
    public Map<String, Object> reviews(
            @PathVariable String productId,
            @RequestParam(name = "rid", required = false) String rid,
            HttpServletRequest request
    ) {
        int starsReviewer1 = -1;
        int starsReviewer2 = -1;

        if (ratingsEnabled) {
            String url = ratingsBaseUrl + "/" + parseId(productId);
            if (rid != null && !rid.isBlank()) {
                url += "?rid=" + rid;
            }
            Map<String, Object> ratings = getJson(url, forwardHeaders(request), Map.of());
            Object ratingsObj = ratings.get("ratings");
            if (ratingsObj instanceof Map<?, ?> ratingMap) {
                starsReviewer1 = numberValue(ratingMap.get("Reviewer1"), -1);
                starsReviewer2 = numberValue(ratingMap.get("Reviewer2"), -1);
            }
        }

        return reviewsResponse(parseId(productId), starsReviewer1, starsReviewer2);
    }

    @GetMapping("/ratings/{productId}")
    public Map<String, Object> ratings(@PathVariable String productId) {
        return getLocalRatings(parseId(productId));
    }

    @PostMapping("/ratings/{productId}")
    public Map<String, Object> putRatings(
            @PathVariable String productId,
            @RequestBody Map<String, Object> ratings
    ) {
        int normalizedProductId = normalize(parseId(productId));
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("id", normalizedProductId);
        result.put("ratings", ratings);
        userAddedRatings.put(normalizedProductId, result);
        return result;
    }

    private Map<String, Object> product(int productId) {
        int normalizedProductId = normalize(productId);
        Map<String, Object> product = new LinkedHashMap<>();
        product.put("id", normalizedProductId);
        product.put("title", String.format("Microservice Field Notes %03d", normalizedProductId));
        product.put("descriptionHtml", String.format("Synthetic Bookinfo record %03d for trace and lineage experiments.", normalizedProductId));
        return product;
    }

    private Map<String, Object> getReviewsWithRetry(int productId, HttpHeaders headers) {
        Map<String, Object> fallback = fallback("reviews unavailable");
        Map<String, Object> result = fallback;
        for (int i = 0; i < 2; i++) {
            result = getJson(reviewsBaseUrl + "/" + productId, headers, fallback);
            if (!result.containsKey("error")) {
                return result;
            }
        }
        return result;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> getJson(String url, HttpHeaders headers, Map<String, Object> fallback) {
        try {
            ResponseEntity<Map> response = restTemplate.exchange(
                    url,
                    HttpMethod.GET,
                    new HttpEntity<>(headers),
                    Map.class
            );
            Map<?, ?> body = response.getBody();
            if (response.getStatusCode().is2xxSuccessful() && body != null) {
                return new LinkedHashMap<>((Map<String, Object>) body);
            }
        } catch (RuntimeException ignored) {
            return fallback;
        }
        return fallback;
    }

    private Map<String, Object> reviewsResponse(int productId, int starsReviewer1, int starsReviewer2) {
        List<Map<String, Object>> reviews = new ArrayList<>();
        reviews.add(review("Reviewer1", "An extremely entertaining play by Shakespeare. The slapstick humour is refreshing!", starsReviewer1));
        reviews.add(review("Reviewer2", "Absolutely fun and entertaining. The play lacks thematic depth when compared to other plays by Shakespeare.", starsReviewer2));

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("id", String.valueOf(parseId(String.valueOf(productId))));
        response.put("podname", podHostname);
        response.put("clustername", System.getenv().getOrDefault("CLUSTER_NAME", ""));
        response.put("reviews", reviews);
        return response;
    }

    private Map<String, Object> review(String reviewer, String text, int stars) {
        Map<String, Object> review = new LinkedHashMap<>();
        review.put("reviewer", reviewer);
        review.put("text", text);
        if (ratingsEnabled) {
            if (stars >= 0) {
                review.put("rating", Map.of("stars", stars, "color", starColor));
            } else {
                review.put("rating", Map.of("error", "Ratings service is currently unavailable"));
            }
        }
        return review;
    }

    private Map<String, Object> getLocalRatings(int productId) {
        int normalizedProductId = normalize(productId);
        if (userAddedRatings.containsKey(normalizedProductId)) {
            return userAddedRatings.get(normalizedProductId);
        }

        Map<String, Object> ratings = new LinkedHashMap<>();
        ratings.put("Reviewer1", 1 + (normalizedProductId % 5));
        ratings.put("Reviewer2", 1 + ((normalizedProductId + 3) % 5));

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("id", normalizedProductId);
        response.put("ratings", ratings);
        return response;
    }

    private HttpHeaders forwardHeaders(HttpServletRequest request) {
        Set<String> allowed = new HashSet<>();
        for (String header : FORWARDED_HEADERS) {
            allowed.add(header.toLowerCase(Locale.ROOT));
        }

        HttpHeaders headers = new HttpHeaders();
        Enumeration<String> names = request.getHeaderNames();
        while (names.hasMoreElements()) {
            String name = names.nextElement();
            if (allowed.contains(name.toLowerCase(Locale.ROOT))) {
                headers.add(name, request.getHeader(name));
            }
        }
        return headers;
    }

    private String renderProductPage(Map<String, Object> product, Map<String, Object> details, Map<String, Object> reviews) {
        return """
                <!doctype html>
                <html>
                  <head><title>Bookinfo Java</title></head>
                  <body>
                    <h1>%s</h1>
                    <h2>Details</h2>
                    <pre>%s</pre>
                    <h2>Reviews</h2>
                    <pre>%s</pre>
                  </body>
                </html>
                """.formatted(escape(String.valueOf(product.get("title"))), escape(details.toString()), escape(reviews.toString()));
    }

    private Map<String, Object> fallback(String message) {
        return Map.of("error", message);
    }

    private int parseId(String raw) {
        try {
            return Integer.parseInt(raw);
        } catch (RuntimeException ignored) {
            return 0;
        }
    }

    private int normalize(int productId) {
        return Math.floorMod(productId, bookCount);
    }

    private int numberValue(Object value, int fallback) {
        if (value instanceof Number number) {
            return number.intValue();
        }
        try {
            return Integer.parseInt(String.valueOf(value));
        } catch (RuntimeException ignored) {
            return fallback;
        }
    }

    private String escape(String value) {
        return value
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;");
    }

    private String capitalize(String value) {
        if (value == null || value.isBlank()) {
            return "Service";
        }
        return value.substring(0, 1).toUpperCase(Locale.ROOT) + value.substring(1);
    }

    private String hostname() {
        try {
            return InetAddress.getLocalHost().getHostName();
        } catch (UnknownHostException ignored) {
            return System.getenv().getOrDefault("HOSTNAME", "");
        }
    }
}
