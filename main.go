package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"database/sql"
	_ "modernc.org/sqlite"

	"golang.org/x/crypto/acme/autocert"
)

type app struct {
	db        *sql.DB
	sessions  *sessionStore
	limiter   *rateLimiter
	templates map[string]templateEntry
	reloadTpl bool
}

type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]time.Time
}

type rateLimiter struct {
	mu                 sync.Mutex
	ipFailures         map[string][]time.Time
	ipBlockedUntil     map[string]time.Time
	globalFailures     []time.Time
	globalBlockedUntil time.Time
}

const (
	ipFailureWindow         = 5 * time.Minute
	ipFailureLimit          = 3
	ipBlockDuration         = 10 * time.Minute
	globalFailureWind       = 10 * time.Minute
	globalFailureLim        = 100
	globalBlockDur          = 5 * time.Minute
	defaultBlogExcerptWords = 25
	defaultLinkedInURL      = "https://www.linkedin.com/in/jovie-velasco-748523150/"
	defaultFacebookURL      = "https://www.facebook.com"
	defaultInstagramURL     = "https://www.instagram.com"
	defaultHTTPAddr         = "localhost:8080"
	defaultHTTPSAddr        = ":443"
	defaultACMEHost         = "awocc.ca"
	defaultACMECache        = "cert-cache"
	defaultACMEEmail        = "marc.gauthier3@gmail.com"
)

func newSessionStore() *sessionStore {
	return &sessionStore{sessions: map[string]time.Time{}}
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{
		ipFailures:     map[string][]time.Time{},
		ipBlockedUntil: map[string]time.Time{},
	}
}

func (r *rateLimiter) check(ip string) (bool, time.Time) {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.globalBlockedUntil.After(now) {
		return false, r.globalBlockedUntil
	}
	if until, ok := r.ipBlockedUntil[ip]; ok {
		if until.After(now) {
			return false, until
		}
		delete(r.ipBlockedUntil, ip)
	}
	r.globalFailures = pruneTimes(r.globalFailures, now.Add(-globalFailureWind))
	if failures, ok := r.ipFailures[ip]; ok {
		r.ipFailures[ip] = pruneTimes(failures, now.Add(-ipFailureWindow))
		if len(r.ipFailures[ip]) == 0 {
			delete(r.ipFailures, ip)
		}
	}
	return true, time.Time{}
}

func (r *rateLimiter) registerFailure(ip string) (time.Time, time.Time) {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()

	failures := r.ipFailures[ip]
	failures = pruneTimes(failures, now.Add(-ipFailureWindow))
	failures = append(failures, now)
	r.ipFailures[ip] = failures

	r.globalFailures = pruneTimes(r.globalFailures, now.Add(-globalFailureWind))
	r.globalFailures = append(r.globalFailures, now)

	var ipBlockedUntil time.Time
	if len(failures) >= ipFailureLimit {
		ipBlockedUntil = now.Add(ipBlockDuration)
		r.ipBlockedUntil[ip] = ipBlockedUntil
		delete(r.ipFailures, ip)
	}

	var globalBlockedUntil time.Time
	if len(r.globalFailures) >= globalFailureLim {
		globalBlockedUntil = now.Add(globalBlockDur)
		r.globalBlockedUntil = globalBlockedUntil
		r.globalFailures = nil
	}

	return ipBlockedUntil, globalBlockedUntil
}

func (r *rateLimiter) clearFailures(ip string) {
	r.mu.Lock()
	delete(r.ipFailures, ip)
	r.mu.Unlock()
}

func pruneTimes(times []time.Time, cutoff time.Time) []time.Time {
	idx := 0
	for _, t := range times {
		if t.After(cutoff) {
			times[idx] = t
			idx++
		}
	}
	return times[:idx]
}

func (s *sessionStore) create() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	token := base64.RawURLEncoding.EncodeToString(b)
	s.mu.Lock()
	s.sessions[token] = time.Now().Add(24 * time.Hour)
	s.mu.Unlock()
	return token
}

func (s *sessionStore) valid(token string) bool {
	if token == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	expires, ok := s.sessions[token]
	if !ok {
		return false
	}
	if time.Now().After(expires) {
		delete(s.sessions, token)
		return false
	}
	return true
}

func (s *sessionStore) delete(token string) {
	if token == "" {
		return
	}
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
}

type pageData struct {
	Title            string
	ShowAdminLogout  bool
	BlogPosts        []blogPost
	Vlogs            []vlogItem
	NewsItems        []newsItem
	ContactEmail     string
	ContactPhone     string
	BlogExcerptWords int
	LinkedInURL      string
	FacebookURL      string
	InstagramURL     string
	BlogPost         *blogPost
	VlogItem         *vlogItem
}

type templateEntry struct {
	tmpl *template.Template
	base string
}

func loadTemplates() (map[string]templateEntry, error) {
	funcs := template.FuncMap{
		"embedURL":      toEmbedURL,
		"telURL":        toTelURL,
		"thumbnailURL":  toThumbnailURL,
		"truncateWords": truncateWords,
	}
	partials, err := filepath.Glob(filepath.Join("templates", "partials", "*.html"))
	if err != nil {
		return nil, err
	}
	basePath := filepath.Join("templates", "base.html")
	adminBasePath := filepath.Join("templates", "base-admin.html")
	pages := map[string]struct {
		file string
		base string
	}{
		"home":            {file: filepath.Join("templates", "home.html"), base: "base"},
		"services":        {file: filepath.Join("templates", "services.html"), base: "base"},
		"news":            {file: filepath.Join("templates", "news.html"), base: "base"},
		"news-item":       {file: filepath.Join("templates", "news-item.html"), base: "base"},
		"blog":            {file: filepath.Join("templates", "blog.html"), base: "base"},
		"blog-item":       {file: filepath.Join("templates", "blog-item.html"), base: "base"},
		"vlog":            {file: filepath.Join("templates", "vlog.html"), base: "base"},
		"vlog-item":       {file: filepath.Join("templates", "vlog-item.html"), base: "base"},
		"about":           {file: filepath.Join("templates", "about.html"), base: "base"},
		"contact":         {file: filepath.Join("templates", "contact.html"), base: "base"},
		"admin-login":     {file: filepath.Join("templates", "admin-login.html"), base: "admin-base"},
		"admin-dashboard": {file: filepath.Join("templates", "admin-dashboard.html"), base: "admin-base"},
	}
	cache := make(map[string]templateEntry)
	for name, cfg := range pages {
		files := append([]string{}, partials...)
		if cfg.base == "admin-base" {
			files = append(files, adminBasePath, cfg.file)
		} else {
			files = append(files, basePath, cfg.file)
		}
		tmpl := template.New("").Funcs(funcs)
		if _, err := tmpl.ParseFiles(files...); err != nil {
			return nil, err
		}
		cache[name] = templateEntry{tmpl: tmpl, base: cfg.base}
	}
	return cache, nil
}

func truncateWords(input string, max int) string {
	if max <= 0 {
		return ""
	}
	words := strings.Fields(input)
	if len(words) <= max {
		return input
	}
	return strings.Join(words[:max], " ") + "..."
}

func toEmbedURL(raw string) template.URL {
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "embed") {
		return template.URL(raw)
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return template.URL(raw)
	}
	if strings.Contains(parsed.Host, "youtu.be") {
		id := strings.TrimPrefix(parsed.Path, "/")
		if id != "" {
			return template.URL("https://www.youtube.com/embed/" + id)
		}
		return template.URL(raw)
	}
	query := parsed.Query()
	if id := query.Get("v"); id != "" {
		return template.URL("https://www.youtube.com/embed/" + id)
	}
	return template.URL(raw)
}

func toThumbnailURL(imageURL, youtubeURL string) string {
	if imageURL != "" {
		return imageURL
	}
	id := extractYouTubeID(youtubeURL)
	if id == "" {
		return ""
	}
	return "https://img.youtube.com/vi/" + id + "/hqdefault.jpg"
}

func extractYouTubeID(raw string) string {
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	host := strings.ToLower(parsed.Host)
	if strings.Contains(host, "youtu.be") {
		return strings.TrimPrefix(parsed.Path, "/")
	}
	if strings.Contains(host, "youtube.com") {
		if strings.HasPrefix(parsed.Path, "/watch") {
			if id := parsed.Query().Get("v"); id != "" {
				return id
			}
		}
		if strings.HasPrefix(parsed.Path, "/embed/") {
			return strings.TrimPrefix(parsed.Path, "/embed/")
		}
		if strings.HasPrefix(parsed.Path, "/shorts/") {
			return strings.TrimPrefix(parsed.Path, "/shorts/")
		}
	}
	return ""
}

func toTelURL(raw string) string {
	if raw == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range raw {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		} else if r == '+' && b.Len() == 0 {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return ""
	}
	return "tel:" + b.String()
}

func main() {
	localMode := false
	for _, arg := range os.Args[1:] {
		if arg == "/local" {
			localMode = true
			break
		}
	}

	db, err := sql.Open("sqlite", filepath.Join("data", "awocc.db"))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if err := migrate(db); err != nil {
		log.Fatal(err)
	}
	if err := ensureDefaultAdmin(db); err != nil {
		log.Fatal(err)
	}

	app := &app{
		db:        db,
		sessions:  newSessionStore(),
		limiter:   newRateLimiter(),
		reloadTpl: localMode,
	}

	templateCache, err := loadTemplates()
	if err != nil {
		log.Fatal(err)
	}
	app.templates = templateCache

	mux := http.NewServeMux()
	mux.HandleFunc("/api/admin/login", app.handleAdminLogin)
	mux.HandleFunc("/api/admin/logout", app.handleAdminLogout)
	mux.HandleFunc("/api/admin/blog", app.handleAdminBlog)
	mux.HandleFunc("/api/admin/blog/", app.handleAdminBlogItem)
	mux.HandleFunc("/api/admin/vlog", app.handleAdminVlog)
	mux.HandleFunc("/api/admin/vlog/", app.handleAdminVlogItem)
	mux.HandleFunc("/api/admin/news", app.handleAdminNews)
	mux.HandleFunc("/api/admin/news/", app.handleAdminNewsItem)
	mux.HandleFunc("/api/admin/settings", app.handleAdminSettings)

	mux.HandleFunc("/api/blog", app.handleBlogList)
	mux.HandleFunc("/api/blog/", app.handleBlogItem)
	mux.HandleFunc("/api/vlog", app.handleVlogList)
	mux.HandleFunc("/api/news", app.handleNewsList)
	mux.HandleFunc("/api/news/", app.handleNewsItem)

	mux.HandleFunc("/admin/login", app.handleAdminLoginPage)
	mux.HandleFunc("/admin/dashboard", app.handleAdminDashboardPage)

	mux.HandleFunc("/services", app.handleServicesPage)
	mux.HandleFunc("/news", app.handleNewsPage)
	mux.HandleFunc("/news/", app.handleNewsItemPage)
	mux.HandleFunc("/vlog", app.handleVlogPage)
	mux.HandleFunc("/blog", app.handleBlogPage)
	mux.HandleFunc("/blog/", app.handleBlogItemPage)
	mux.HandleFunc("/about", app.handleAboutPage)
	mux.HandleFunc("/contact", app.handleContactPage)
	mux.HandleFunc("/", app.handleHomePage)

	assetsDir := filepath.Join("public", "assets")
	mux.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir(assetsDir))))
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join(assetsDir, "favicon.ico"))
	})

	addr := defaultHTTPAddr
	httpOnly := localMode
	if localMode {
		addr = defaultHTTPAddr
	}
	if httpOnly {
		log.Printf("starting HTTP server on %s", addr)
		log.Fatal(http.ListenAndServe(addr, mux))
	}

	hosts := strings.Split(defaultACMEHost, ",")
	for i := range hosts {
		hosts[i] = strings.TrimSpace(hosts[i])
	}
	if len(hosts) == 0 || hosts[0] == "" {
		log.Fatal("ACME host is required for HTTPS")
	}

	certCache := defaultACMECache
	manager := &autocert.Manager{
		Cache:      autocert.DirCache(certCache),
		Prompt:     autocert.AcceptTOS,
		Email:      defaultACMEEmail,
		HostPolicy: autocert.HostWhitelist(hosts...),
	}

	go func() {
		redirect := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host := r.Host
			if strings.Contains(host, ":") {
				host = strings.Split(host, ":")[0]
			}
			target := "https://" + host + r.URL.RequestURI()
			http.Redirect(w, r, target, http.StatusMovedPermanently)
		})
		log.Printf("starting HTTP-01 challenge server on :80")
		if err := http.ListenAndServe(":80", manager.HTTPHandler(redirect)); err != nil {
			log.Fatal(err)
		}
	}()

	httpsAddr := defaultHTTPSAddr
	server := &http.Server{
		Addr:      httpsAddr,
		Handler:   mux,
		TLSConfig: manager.TLSConfig(),
	}
	log.Printf("starting HTTPS server on %s", httpsAddr)
	log.Fatal(server.ListenAndServeTLS("", ""))
}

func migrate(db *sql.DB) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS admin_users (
			username TEXT PRIMARY KEY,
			password TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS blog_posts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			title TEXT NOT NULL,
			body TEXT NOT NULL,
			published INTEGER NOT NULL DEFAULT 0,
			published_at TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS vlogs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			title TEXT NOT NULL,
			description TEXT NOT NULL,
			youtube_url TEXT NOT NULL,
			image_url TEXT NOT NULL DEFAULT '',
			published INTEGER NOT NULL DEFAULT 0,
			published_at TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS news_items (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			title TEXT NOT NULL,
			slug TEXT NOT NULL UNIQUE,
			description TEXT NOT NULL,
			body TEXT NOT NULL,
			published INTEGER NOT NULL DEFAULT 0,
			published_at TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS site_settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);`,
	}
	for _, q := range queries {
		if _, err := db.Exec(q); err != nil {
			return err
		}
	}
	if err := ensureColumn(db, "vlogs", "image_url", "ALTER TABLE vlogs ADD COLUMN image_url TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := ensureVlogSchema(db); err != nil {
		return err
	}
	if err := ensureBlogSchema(db); err != nil {
		return err
	}
	if err := ensureDefaultSetting(db, "contact_email", "info@awocc.ca"); err != nil {
		return err
	}
	if err := ensureDefaultSetting(db, "contact_phone", "(613) 806-7544"); err != nil {
		return err
	}
	if err := ensureDefaultSetting(db, "blog_excerpt_words", strconv.Itoa(defaultBlogExcerptWords)); err != nil {
		return err
	}
	if err := ensureDefaultSetting(db, "linkedin_url", defaultLinkedInURL); err != nil {
		return err
	}
	if err := ensureDefaultSetting(db, "facebook_url", defaultFacebookURL); err != nil {
		return err
	}
	if err := ensureDefaultSetting(db, "instagram_url", defaultInstagramURL); err != nil {
		return err
	}
	return nil
}

func ensureDefaultAdmin(db *sql.DB) error {
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM admin_users WHERE username = ?", "jovie.v80@gmail.com").Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		if _, err := db.Exec(`INSERT INTO admin_users (username, password) VALUES (?, ?)`, "jovie.v80@gmail.com", "bella123!!"); err != nil {
			return err
		}
	}
	return nil
}

func ensureDefaultSetting(db *sql.DB, key, value string) error {
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM site_settings WHERE key = ?", key).Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		if _, err := db.Exec(`INSERT INTO site_settings (key, value) VALUES (?, ?)`, key, value); err != nil {
			return err
		}
	}
	return nil
}

func ensureColumn(db *sql.DB, table, column, ddl string) error {
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var cid int
		var name, ctype string
		var notNull int
		var dflt sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dflt, &pk); err != nil {
			return err
		}
		if name == column {
			return nil
		}
	}
	_, err = db.Exec(ddl)
	return err
}

func ensureVlogSchema(db *sql.DB) error {
	cols := map[string]bool{}
	rows, err := db.Query("PRAGMA table_info(vlogs)")
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var cid int
		var name, ctype string
		var notNull int
		var dflt sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dflt, &pk); err != nil {
			return err
		}
		cols[name] = true
	}
	if !cols["slug"] && !cols["body"] {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`CREATE TABLE vlogs_new (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		title TEXT NOT NULL,
		description TEXT NOT NULL,
		youtube_url TEXT NOT NULL,
		image_url TEXT NOT NULL DEFAULT '',
		published INTEGER NOT NULL DEFAULT 0,
		published_at TEXT
	);`); err != nil {
		tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`INSERT INTO vlogs_new (id, title, description, youtube_url, image_url, published, published_at)
		SELECT id, title, description, youtube_url, image_url, published, published_at FROM vlogs`); err != nil {
		tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`DROP TABLE vlogs`); err != nil {
		tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`ALTER TABLE vlogs_new RENAME TO vlogs`); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

func ensureBlogSchema(db *sql.DB) error {
	cols := map[string]bool{}
	rows, err := db.Query("PRAGMA table_info(blog_posts)")
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var cid int
		var name, ctype string
		var notNull int
		var dflt sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dflt, &pk); err != nil {
			return err
		}
		cols[name] = true
	}
	if !cols["slug"] && !cols["excerpt"] {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`CREATE TABLE blog_posts_new (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		title TEXT NOT NULL,
		body TEXT NOT NULL,
		published INTEGER NOT NULL DEFAULT 0,
		published_at TEXT
	);`); err != nil {
		tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`INSERT INTO blog_posts_new (id, title, body, published, published_at)
		SELECT id, title, body, published, published_at FROM blog_posts`); err != nil {
		tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`DROP TABLE blog_posts`); err != nil {
		tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`ALTER TABLE blog_posts_new RENAME TO blog_posts`); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (a *app) renderPage(w http.ResponseWriter, templateName string, data pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if a.reloadTpl {
		cache, err := loadTemplates()
		if err != nil {
			log.Printf("template reload error: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		a.templates = cache
	}
	entry, ok := a.templates[templateName]
	if !ok {
		http.Error(w, "page not found", http.StatusNotFound)
		return
	}
	if data.ContactEmail == "" || data.ContactPhone == "" || data.BlogExcerptWords == 0 || data.LinkedInURL == "" || data.FacebookURL == "" || data.InstagramURL == "" {
		settings, err := a.fetchSiteSettings()
		if err != nil {
			log.Printf("settings error: %v", err)
		} else {
			if data.ContactEmail == "" {
				data.ContactEmail = settings.Email
			}
			if data.ContactPhone == "" {
				data.ContactPhone = settings.Phone
			}
			if data.BlogExcerptWords == 0 && settings.BlogExcerptWords > 0 {
				data.BlogExcerptWords = settings.BlogExcerptWords
			}
			if data.LinkedInURL == "" {
				data.LinkedInURL = settings.LinkedInURL
			}
			if data.FacebookURL == "" {
				data.FacebookURL = settings.FacebookURL
			}
			if data.InstagramURL == "" {
				data.InstagramURL = settings.InstagramURL
			}
		}
	}
	if data.BlogExcerptWords == 0 {
		data.BlogExcerptWords = defaultBlogExcerptWords
	}
	if data.LinkedInURL == "" {
		data.LinkedInURL = defaultLinkedInURL
	}
	if data.FacebookURL == "" {
		data.FacebookURL = defaultFacebookURL
	}
	if data.InstagramURL == "" {
		data.InstagramURL = defaultInstagramURL
	}
	if err := entry.tmpl.ExecuteTemplate(w, entry.base, data); err != nil {
		log.Printf("template error: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
	}
}

func (a *app) fetchBlogPosts(publishedOnly bool, limit int) ([]blogPost, error) {
	query := `SELECT id, title, body, published, COALESCE(published_at, '')
		FROM blog_posts`
	args := []interface{}{}
	if publishedOnly {
		query += " WHERE published = 1"
	}
	query += " ORDER BY published_at DESC"
	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}
	rows, err := a.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var posts []blogPost
	for rows.Next() {
		var post blogPost
		var published int
		if err := rows.Scan(&post.ID, &post.Title, &post.Body, &published, &post.PublishedAt); err != nil {
			return nil, err
		}
		post.Published = published == 1
		posts = append(posts, post)
	}
	return posts, nil
}

func (a *app) fetchBlogPostByID(id int) (blogPost, error) {
	var post blogPost
	var published int
	row := a.db.QueryRow(`SELECT id, title, body, published, COALESCE(published_at, '')
		FROM blog_posts WHERE id = ? AND published = 1`, id)
	if err := row.Scan(&post.ID, &post.Title, &post.Body, &published, &post.PublishedAt); err != nil {
		return post, err
	}
	post.Published = published == 1
	return post, nil
}

func (a *app) fetchVlogs(publishedOnly bool, limit int) ([]vlogItem, error) {
	query := `SELECT id, title, description, youtube_url, image_url, published, COALESCE(published_at, '')
		FROM vlogs`
	args := []interface{}{}
	if publishedOnly {
		query += " WHERE published = 1"
	}
	query += " ORDER BY published_at DESC"
	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}
	rows, err := a.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var vlogs []vlogItem
	for rows.Next() {
		var item vlogItem
		var published int
		if err := rows.Scan(&item.ID, &item.Title, &item.Description, &item.YoutubeURL, &item.ImageURL, &published, &item.PublishedAt); err != nil {
			return nil, err
		}
		item.Published = published == 1
		vlogs = append(vlogs, item)
	}
	return vlogs, nil
}

func (a *app) fetchContactInfo() (contactInfo, error) {
	settings, err := a.fetchSiteSettings()
	if err != nil {
		return contactInfo{}, err
	}
	return contactInfo{Email: settings.Email, Phone: settings.Phone}, nil
}

func (a *app) fetchSiteSettings() (siteSettings, error) {
	rows, err := a.db.Query(`SELECT key, value FROM site_settings WHERE key IN (?, ?, ?, ?, ?, ?)`,
		"contact_email", "contact_phone", "blog_excerpt_words", "linkedin_url", "facebook_url", "instagram_url")
	if err != nil {
		return siteSettings{}, err
	}
	defer rows.Close()

	info := siteSettings{
		BlogExcerptWords: defaultBlogExcerptWords,
		LinkedInURL:      defaultLinkedInURL,
		FacebookURL:      defaultFacebookURL,
		InstagramURL:     defaultInstagramURL,
	}
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return siteSettings{}, err
		}
		switch key {
		case "contact_email":
			info.Email = value
		case "contact_phone":
			info.Phone = value
		case "blog_excerpt_words":
			parsed, err := strconv.Atoi(value)
			if err == nil && parsed > 0 {
				info.BlogExcerptWords = parsed
			}
		case "linkedin_url":
			info.LinkedInURL = value
		case "facebook_url":
			info.FacebookURL = value
		case "instagram_url":
			info.InstagramURL = value
		}
	}
	return info, nil
}

func (a *app) fetchNewsItems(publishedOnly bool, limit int) ([]newsItem, error) {
	query := `SELECT id, title, slug, description, body, published, COALESCE(published_at, '')
		FROM news_items`
	args := []interface{}{}
	if publishedOnly {
		query += " WHERE published = 1"
	}
	query += " ORDER BY published_at DESC"
	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}
	rows, err := a.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []newsItem
	for rows.Next() {
		var item newsItem
		var published int
		if err := rows.Scan(&item.ID, &item.Title, &item.Slug, &item.Description, &item.Body, &published, &item.PublishedAt); err != nil {
			return nil, err
		}
		item.Published = published == 1
		items = append(items, item)
	}
	return items, nil
}

func (a *app) fetchNewsItemByID(id int) (newsItem, error) {
	var item newsItem
	var published int
	row := a.db.QueryRow(`SELECT id, title, slug, description, body, published, COALESCE(published_at, '')
		FROM news_items WHERE id = ? AND published = 1`, id)
	if err := row.Scan(&item.ID, &item.Title, &item.Slug, &item.Description, &item.Body, &published, &item.PublishedAt); err != nil {
		return item, err
	}
	item.Published = published == 1
	return item, nil
}

type blogPost struct {
	ID          int    `json:"id"`
	Title       string `json:"title"`
	Body        string `json:"body"`
	Published   bool   `json:"published"`
	PublishedAt string `json:"published_at"`
}

type vlogItem struct {
	ID          int    `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	YoutubeURL  string `json:"youtube_url"`
	ImageURL    string `json:"image_url"`
	Published   bool   `json:"published"`
	PublishedAt string `json:"published_at"`
}

type newsItem struct {
	ID          int    `json:"id"`
	Title       string `json:"title"`
	Slug        string `json:"slug"`
	Description string `json:"description"`
	Body        string `json:"body"`
	Published   bool   `json:"published"`
	PublishedAt string `json:"published_at"`
}

type contactInfo struct {
	Email string `json:"email"`
	Phone string `json:"phone"`
}

type siteSettings struct {
	Email            string `json:"email"`
	Phone            string `json:"phone"`
	BlogExcerptWords int    `json:"blog_excerpt_words"`
	LinkedInURL      string `json:"linkedin_url"`
	FacebookURL      string `json:"facebook_url"`
	InstagramURL     string `json:"instagram_url"`
}

func (a *app) handleHomePage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	blogs, err := a.fetchBlogPosts(true, 3)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	vlogs, err := a.fetchVlogs(true, 3)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	a.renderPage(w, "home", pageData{
		Title:     "AWOCC.ca | Advanced Wound Ostomy Care Consulting",
		BlogPosts: blogs,
		Vlogs:     vlogs,
	})
}

func (a *app) handleServicesPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/services" {
		http.NotFound(w, r)
		return
	}
	a.renderPage(w, "services", pageData{
		Title: "Our Services | AWOCC.ca",
	})
}

func (a *app) handleNewsPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/news" {
		http.NotFound(w, r)
		return
	}
	items, err := a.fetchNewsItems(true, 0)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	a.renderPage(w, "news", pageData{
		Title:     "News & Events | AWOCC.ca",
		NewsItems: items,
	})
}

func (a *app) handleNewsItemPage(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, "/news/") {
		http.NotFound(w, r)
		return
	}
	idStr := strings.TrimPrefix(r.URL.Path, "/news/")
	if idStr == "" {
		http.NotFound(w, r)
		return
	}
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	item, err := a.fetchNewsItemByID(id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	a.renderPage(w, "news-item", pageData{
		Title: item.Title + " | AWOCC.ca",
		NewsItems: []newsItem{
			item,
		},
	})
}

func (a *app) handleBlogPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/blog" {
		http.NotFound(w, r)
		return
	}
	blogs, err := a.fetchBlogPosts(true, 0)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	a.renderPage(w, "blog", pageData{
		Title:     "Blog | AWOCC.ca",
		BlogPosts: blogs,
	})
}

func (a *app) handleBlogItemPage(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, "/blog/") {
		http.NotFound(w, r)
		return
	}
	idStr := strings.TrimPrefix(r.URL.Path, "/blog/")
	if idStr == "" {
		http.NotFound(w, r)
		return
	}
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	post, err := a.fetchBlogPostByID(id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	a.renderPage(w, "blog-item", pageData{
		Title:    post.Title + " | AWOCC.ca",
		BlogPost: &post,
	})
}

func (a *app) handleVlogPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/vlog" {
		http.NotFound(w, r)
		return
	}
	vlogs, err := a.fetchVlogs(true, 0)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	a.renderPage(w, "vlog", pageData{
		Title: "Vlog | AWOCC.ca",
		Vlogs: vlogs,
	})
}

func (a *app) handleAboutPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/about" {
		http.NotFound(w, r)
		return
	}
	a.renderPage(w, "about", pageData{
		Title: "About Jovie | AWOCC.ca",
	})
}

func (a *app) handleContactPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/contact" {
		http.NotFound(w, r)
		return
	}
	a.renderPage(w, "contact", pageData{
		Title: "Contact | AWOCC.ca",
	})
}

func (a *app) handleAdminLoginPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/admin/login" {
		http.NotFound(w, r)
		return
	}
	a.renderPage(w, "admin-login", pageData{
		Title: "Admin Login | AWOCC.ca",
	})
}

func (a *app) handleAdminDashboardPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/admin/dashboard" {
		http.NotFound(w, r)
		return
	}
	if !a.requireAdminPage(w, r) {
		return
	}
	a.renderPage(w, "admin-dashboard", pageData{
		Title:           "Admin Dashboard | AWOCC.ca",
		ShowAdminLogout: true,
	})
}

func (a *app) handleBlogList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	posts, err := a.fetchBlogPosts(true, 0)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, posts)
}

func (a *app) handleBlogItem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	idStr := strings.TrimPrefix(r.URL.Path, "/api/blog/")
	if idStr == "" {
		writeError(w, http.StatusBadRequest, "missing id")
		return
	}
	id, err := strconv.Atoi(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	post, err := a.fetchBlogPostByID(id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, post)
}

func (a *app) handleVlogList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	vlogs, err := a.fetchVlogs(true, 0)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, vlogs)
}

func (a *app) handleVlogItem(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotFound, "not found")
}

func (a *app) handleNewsList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	items, err := a.fetchNewsItems(true, 0)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (a *app) handleNewsItem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	idStr := strings.TrimPrefix(r.URL.Path, "/api/news/")
	if idStr == "" {
		writeError(w, http.StatusBadRequest, "missing id")
		return
	}
	id, err := strconv.Atoi(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	item, err := a.fetchNewsItemByID(id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (a *app) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	ip := clientIP(r)
	if ok, until := a.limiter.check(ip); !ok {
		writeRateLimit(w, until)
		return
	}
	var payload struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	var storedPassword string
	if err := a.db.QueryRow("SELECT password FROM admin_users WHERE username = ?", payload.Username).Scan(&storedPassword); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			ipBlocked, globalBlocked := a.limiter.registerFailure(ip)
			if !globalBlocked.IsZero() {
				writeRateLimit(w, globalBlocked)
				return
			}
			if !ipBlocked.IsZero() {
				writeRateLimit(w, ipBlocked)
				return
			}
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if payload.Password != storedPassword {
		ipBlocked, globalBlocked := a.limiter.registerFailure(ip)
		if !globalBlocked.IsZero() {
			writeRateLimit(w, globalBlocked)
			return
		}
		if !ipBlocked.IsZero() {
			writeRateLimit(w, ipBlocked)
			return
		}
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	a.limiter.clearFailures(ip)
	token := a.sessions.create()
	if token == "" {
		writeError(w, http.StatusInternalServerError, "could not create session")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "awocc_admin",
		Value:    token,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
		MaxAge:   86400,
		Secure:   r.TLS != nil,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *app) handleAdminLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	cookie, _ := r.Cookie("awocc_admin")
	if cookie != nil {
		a.sessions.delete(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "awocc_admin",
		Value:    "",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
		MaxAge:   -1,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *app) handleAdminBlog(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		rows, err := a.db.Query(`SELECT id, title, body, published, COALESCE(published_at, '')
			FROM blog_posts ORDER BY id DESC`)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "database error")
			return
		}
		defer rows.Close()

		var posts []blogPost
		for rows.Next() {
			var post blogPost
			var published int
			if err := rows.Scan(&post.ID, &post.Title, &post.Body, &published, &post.PublishedAt); err != nil {
				writeError(w, http.StatusInternalServerError, "database error")
				return
			}
			post.Published = published == 1
			posts = append(posts, post)
		}
		writeJSON(w, http.StatusOK, posts)
	case http.MethodPost:
		var post blogPost
		if err := json.NewDecoder(r.Body).Decode(&post); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json")
			return
		}
		if post.Title == "" {
			writeError(w, http.StatusBadRequest, "title required")
			return
		}
		published := 0
		if post.Published {
			published = 1
		}
		_, err := a.db.Exec(`INSERT INTO blog_posts (title, body, published, published_at)
			VALUES (?, ?, ?, ?)`,
			post.Title, post.Body, published, post.PublishedAt)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "database error")
			return
		}
		writeJSON(w, http.StatusCreated, map[string]string{"status": "created"})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (a *app) handleAdminBlogItem(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r) {
		return
	}
	idStr := strings.TrimPrefix(r.URL.Path, "/api/admin/blog/")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	switch r.Method {
	case http.MethodPut:
		var post blogPost
		if err := json.NewDecoder(r.Body).Decode(&post); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json")
			return
		}
		published := 0
		if post.Published {
			published = 1
		}
		_, err = a.db.Exec(`UPDATE blog_posts SET title = ?, body = ?, published = ?, published_at = ?
			WHERE id = ?`, post.Title, post.Body, published, post.PublishedAt, id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "database error")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
	case http.MethodDelete:
		if _, err := a.db.Exec(`DELETE FROM blog_posts WHERE id = ?`, id); err != nil {
			writeError(w, http.StatusInternalServerError, "database error")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (a *app) handleAdminVlog(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		rows, err := a.db.Query(`SELECT id, title, description, youtube_url, image_url, published, COALESCE(published_at, '')
			FROM vlogs ORDER BY id DESC`)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "database error")
			return
		}
		defer rows.Close()

		var vlogs []vlogItem
		for rows.Next() {
			var item vlogItem
			var published int
			if err := rows.Scan(&item.ID, &item.Title, &item.Description, &item.YoutubeURL, &item.ImageURL, &published, &item.PublishedAt); err != nil {
				writeError(w, http.StatusInternalServerError, "database error")
				return
			}
			item.Published = published == 1
			vlogs = append(vlogs, item)
		}
		writeJSON(w, http.StatusOK, vlogs)
	case http.MethodPost:
		var item vlogItem
		if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json")
			return
		}
		if item.Title == "" || item.YoutubeURL == "" {
			writeError(w, http.StatusBadRequest, "title and youtube_url required")
			return
		}
		published := 0
		if item.Published {
			published = 1
		}
		_, err := a.db.Exec(`INSERT INTO vlogs (title, description, youtube_url, image_url, published, published_at)
			VALUES (?, ?, ?, ?, ?, ?)`,
			item.Title, item.Description, item.YoutubeURL, item.ImageURL, published, item.PublishedAt)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "database error")
			return
		}
		writeJSON(w, http.StatusCreated, map[string]string{"status": "created"})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (a *app) handleAdminVlogItem(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r) {
		return
	}
	idStr := strings.TrimPrefix(r.URL.Path, "/api/admin/vlog/")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	switch r.Method {
	case http.MethodPut:
		var item vlogItem
		if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json")
			return
		}
		published := 0
		if item.Published {
			published = 1
		}
		_, err = a.db.Exec(`UPDATE vlogs SET title = ?, description = ?, youtube_url = ?, image_url = ?, published = ?, published_at = ?
			WHERE id = ?`, item.Title, item.Description, item.YoutubeURL, item.ImageURL, published, item.PublishedAt, id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "database error")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
	case http.MethodDelete:
		if _, err := a.db.Exec(`DELETE FROM vlogs WHERE id = ?`, id); err != nil {
			writeError(w, http.StatusInternalServerError, "database error")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (a *app) handleAdminNews(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		rows, err := a.db.Query(`SELECT id, title, slug, description, body, published, COALESCE(published_at, '')
			FROM news_items ORDER BY id DESC`)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "database error")
			return
		}
		defer rows.Close()

		var items []newsItem
		for rows.Next() {
			var item newsItem
			var published int
			if err := rows.Scan(&item.ID, &item.Title, &item.Slug, &item.Description, &item.Body, &published, &item.PublishedAt); err != nil {
				writeError(w, http.StatusInternalServerError, "database error")
				return
			}
			item.Published = published == 1
			items = append(items, item)
		}
		writeJSON(w, http.StatusOK, items)
	case http.MethodPost:
		var item newsItem
		if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json")
			return
		}
		if item.Title == "" || item.Slug == "" {
			writeError(w, http.StatusBadRequest, "title and slug required")
			return
		}
		published := 0
		if item.Published {
			published = 1
		}
		_, err := a.db.Exec(`INSERT INTO news_items (title, slug, description, body, published, published_at)
			VALUES (?, ?, ?, ?, ?, ?)`,
			item.Title, item.Slug, item.Description, item.Body, published, item.PublishedAt)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "database error")
			return
		}
		writeJSON(w, http.StatusCreated, map[string]string{"status": "created"})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (a *app) handleAdminNewsItem(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r) {
		return
	}
	idStr := strings.TrimPrefix(r.URL.Path, "/api/admin/news/")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	switch r.Method {
	case http.MethodPut:
		var item newsItem
		if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json")
			return
		}
		published := 0
		if item.Published {
			published = 1
		}
		_, err = a.db.Exec(`UPDATE news_items SET title = ?, slug = ?, description = ?, body = ?, published = ?, published_at = ?
			WHERE id = ?`, item.Title, item.Slug, item.Description, item.Body, published, item.PublishedAt, id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "database error")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
	case http.MethodDelete:
		if _, err := a.db.Exec(`DELETE FROM news_items WHERE id = ?`, id); err != nil {
			writeError(w, http.StatusInternalServerError, "database error")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (a *app) handleAdminSettings(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		info, err := a.fetchSiteSettings()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "database error")
			return
		}
		writeJSON(w, http.StatusOK, info)
	case http.MethodPut:
		var payload siteSettings
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json")
			return
		}
		if payload.Email == "" || payload.Phone == "" {
			writeError(w, http.StatusBadRequest, "email and phone required")
			return
		}
		if payload.BlogExcerptWords <= 0 {
			writeError(w, http.StatusBadRequest, "blog excerpt words required")
			return
		}
		if payload.LinkedInURL == "" || payload.FacebookURL == "" || payload.InstagramURL == "" {
			writeError(w, http.StatusBadRequest, "social links required")
			return
		}
		if err := a.upsertSetting("contact_email", payload.Email); err != nil {
			writeError(w, http.StatusInternalServerError, "database error")
			return
		}
		if err := a.upsertSetting("contact_phone", payload.Phone); err != nil {
			writeError(w, http.StatusInternalServerError, "database error")
			return
		}
		if err := a.upsertSetting("blog_excerpt_words", strconv.Itoa(payload.BlogExcerptWords)); err != nil {
			writeError(w, http.StatusInternalServerError, "database error")
			return
		}
		if err := a.upsertSetting("linkedin_url", payload.LinkedInURL); err != nil {
			writeError(w, http.StatusInternalServerError, "database error")
			return
		}
		if err := a.upsertSetting("facebook_url", payload.FacebookURL); err != nil {
			writeError(w, http.StatusInternalServerError, "database error")
			return
		}
		if err := a.upsertSetting("instagram_url", payload.InstagramURL); err != nil {
			writeError(w, http.StatusInternalServerError, "database error")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (a *app) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	cookie, err := r.Cookie("awocc_admin")
	if err != nil || !a.sessions.valid(cookie.Value) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return false
	}
	return true
}

func (a *app) requireAdminPage(w http.ResponseWriter, r *http.Request) bool {
	cookie, err := r.Cookie("awocc_admin")
	if err != nil || !a.sessions.valid(cookie.Value) {
		http.Redirect(w, r, "/admin/login", http.StatusFound)
		return false
	}
	return true
}

func (a *app) upsertSetting(key, value string) error {
	_, err := a.db.Exec(`INSERT INTO site_settings (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

func clientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

func writeRateLimit(w http.ResponseWriter, until time.Time) {
	retry := int(time.Until(until).Seconds())
	if retry < 0 {
		retry = 0
	}
	if !until.IsZero() {
		w.Header().Set("Retry-After", strconv.Itoa(retry))
	}
	writeError(w, http.StatusTooManyRequests, "too many attempts")
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if payload != nil {
		_ = json.NewEncoder(w).Encode(payload)
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
