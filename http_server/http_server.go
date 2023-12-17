package http_server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/samber/lo"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/danthegoodman1/GoAPITemplate/gologger"
	"github.com/danthegoodman1/GoAPITemplate/utils"
	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/rs/zerolog"
	"golang.org/x/net/http2"
)

var logger = gologger.NewLogger()

type HTTPServer struct {
	Echo *echo.Echo
}

type CustomValidator struct {
	validator *validator.Validate
}

func StartHTTPServer() *HTTPServer {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%s", utils.GetEnvOrDefault("HTTP_PORT", "8080")))
	if err != nil {
		logger.Error().Err(err).Msg("error creating tcp listener, exiting")
		os.Exit(1)
	}
	s := &HTTPServer{
		Echo: echo.New(),
	}
	s.Echo.HideBanner = true
	s.Echo.HidePort = true
	s.Echo.JSONSerializer = &utils.NoEscapeJSONSerializer{}

	s.Echo.Use(CreateReqContext)
	s.Echo.Use(LoggerMiddleware)
	s.Echo.Use(middleware.CORS())
	s.Echo.Validator = &CustomValidator{validator: validator.New()}

	// technical - no auth
	s.Echo.GET("/hc", s.HealthCheck)
	s.Echo.POST("/", s.HandlePost)

	s.Echo.Listener = listener
	go func() {
		logger.Info().Msg("starting h2c server on " + listener.Addr().String())
		err := s.Echo.StartH2CServer("", &http2.Server{})
		// stop the broker
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error().Err(err).Msg("failed to start h2c server, exiting")
			os.Exit(1)
		}
	}()

	return s
}

func (cv *CustomValidator) Validate(i interface{}) error {
	if err := cv.validator.Struct(i); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	return nil
}

func ValidateRequest(c echo.Context, s interface{}) error {
	if err := c.Bind(s); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if err := c.Validate(s); err != nil {
		return err
	}
	return nil
}

func (*HTTPServer) HealthCheck(c echo.Context) error {
	return c.String(http.StatusOK, "ok")
}

func (s *HTTPServer) Shutdown(ctx context.Context) error {
	err := s.Echo.Shutdown(ctx)
	return err
}

func LoggerMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		start := time.Now()
		if err := next(c); err != nil {
			// default handler
			c.Error(err)
		}
		stop := time.Since(start)
		// Log otherwise
		logger := zerolog.Ctx(c.Request().Context())
		req := c.Request()
		res := c.Response()

		p := req.URL.Path
		if p == "" {
			p = "/"
		}

		cl := req.Header.Get(echo.HeaderContentLength)
		if cl == "" {
			cl = "0"
		}
		logger.Debug().Str("method", req.Method).Str("remote_ip", c.RealIP()).Str("req_uri", req.RequestURI).Str("handler_path", c.Path()).Str("path", p).Int("status", res.Status).Int64("latency_ns", int64(stop)).Str("protocol", req.Proto).Str("bytes_in", cl).Int64("bytes_out", res.Size).Msg("req recived")
		return nil
	}
}

func getHMAC(key []byte, data []byte) []byte {
	hash := hmac.New(sha256.New, key)
	hash.Write(data)
	return hash.Sum(nil)
}

func getSHA256(data []byte) []byte {
	hash := sha256.New()
	hash.Write(data)
	return hash.Sum(nil)
}

var (
	ErrNoSignedHeaders = errors.New("no signed headers")
)

func getCanonicalRequest(c echo.Context, body []byte) (string, error) {
	s := ""
	s += c.Request().Method + "\n"
	s += c.Request().URL.EscapedPath() + "\n"
	s += c.Request().URL.Query().Encode() + "\n"

	signedHeadersList, found := lo.Find(strings.Split(c.Request().Header.Get("Authorization"), ", "), func(item string) bool {
		return strings.HasPrefix(item, "SignedHeaders")
	})
	if !found {
		return "", ErrNoSignedHeaders
	}

	signedHeaders := strings.Split(strings.ReplaceAll(strings.ReplaceAll(signedHeadersList, "SignedHeaders=", ""), ",", ""), ";")
	sort.Strings(signedHeaders) // must be sorted alphabetically
	for _, header := range signedHeaders {
		if header == "host" {
			// For some reason the host header was blank (thanks echo?)
			s += strings.ToLower(header) + ":" + strings.TrimSpace(c.Request().Host) + "\n"
			continue
		}
		s += strings.ToLower(header) + ":" + strings.TrimSpace(c.Request().Header.Get(header)) + "\n"
	}

	s += "\n" // examples have this JESUS WHY DOCS FFS

	s += strings.Join(signedHeaders, ";") + "\n"

	s += fmt.Sprintf("%x", getSHA256(body))

	return s, nil
}

func getStringToSign(c echo.Context, canonicalRequest string) string {
	s := "AWS4-HMAC-SHA256" + "\n"
	s += c.Request().Header.Get("X-Amz-Date") + "\n"

	scope := c.Request().Header.Get("X-Amz-Date")[:8] + "/" + "us-east-1" + "/" + "dynamodb" + "/aws4_request"
	s += scope + "\n"
	s += fmt.Sprintf("%x", getSHA256([]byte(canonicalRequest)))

	return s
}

func getSigningKey(c echo.Context) []byte {
	dateKey := getHMAC([]byte("AWS4"+"testpassword"), []byte(c.Request().Header.Get("X-Amz-Date")[:8]))
	dateRegionKey := getHMAC(dateKey, []byte("us-east-1"))
	dateRegionServiceKey := getHMAC(dateRegionKey, []byte("dynamodb"))
	signingKey := getHMAC(dateRegionServiceKey, []byte("aws4_request"))
	return signingKey
}

func (s *HTTPServer) HandlePost(c echo.Context) error {

	for header, vals := range c.Request().Header {
		for _, val := range vals {
			fmt.Printf("\t%s: %s\n", header, val)
		}
	}

	// awsID := "testuser"
	// awsSecret := "testpassword"
	defer c.Request().Body.Close()
	bodyBytes, err := io.ReadAll(c.Request().Body)
	if err != nil {
		return fmt.Errorf("error in ReadAll of body: %w", err)
	}

	canonicalRequest, err := getCanonicalRequest(c, bodyBytes)
	if err != nil {
		return fmt.Errorf("error in getCanonicalRequest: %w", err)
	}
	fmt.Printf("\n============= Canonical request:\n%s\n", canonicalRequest)
	stringToSign := getStringToSign(c, canonicalRequest)
	fmt.Printf("\n============= String to sign:\n%s\n", stringToSign)

	signingKey := getSigningKey(c)
	signature := fmt.Sprintf("%x", getHMAC(signingKey, []byte(stringToSign)))

	fmt.Printf("\nFINAL Signature: %s\n", signature)

	providedSignature, _ := lo.Find(strings.Split(c.Request().Header.Get("Authorization"), ", "), func(item string) bool {
		return strings.HasPrefix(item, "Signature")
	})
	providedSignature = strings.Split(providedSignature, "=")[1]

	fmt.Println(providedSignature)
	fmt.Println(signature)

	return c.String(http.StatusOK, "Signature is valid")
}
