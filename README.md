Goal
Build a Go (Golang) website with a SQLite database to host blog and vlog content for a nursing consultant in Ontario.

Client
Jovie Velasco, RN, MClSc, NSWOC, WOCC(C) 
(Nurse Specialized in Wound, Ostomy, and Continence).

Site Name
AWOCC.ca (Advanced Wound Ostomy Care Consulting)

Inspiration (design and content tone)
- https://www.myostomycare.com/meet-our-nurses/nswoc/

Reference (NSWOC information)
- https://www.nswoc.ca/

Required Pages
- Home (landing page)
- Our Services
- News & Events
- Vlog (list of items on one page, each links to a video page)
- Blog (list of articles; each opens a full article page)
- About Jovie
- Contact

Stay Connected (links)
- LinkedIn
- Facebook
- Instagram

Admin Requirements
- Admin login page
- Admin can create, edit, and publish blog posts
- Admin can create and edit vlog entries with:
  - Title
  - Description
  - YouTube video link
  - Supporting text

Content Focus
Educational resources and updates about wound, ostomy, and continence care, tailored for the Ontario audience.

Development
- Run: `HTTP_ONLY=1 HTTP_ADDR=:8080 go run .`
- Templates auto-reload when `HTTP_ONLY=1` or `TEMPLATE_RELOAD=1`.
- Templates live in `/templates` and are rendered server-side.
- Static assets (CSS/JS/images) live in `/public/assets`.

Production (Let's Encrypt)
- Run: `ACME_HOSTS=awocc.ca,www.awocc.ca ACME_EMAIL=you@example.com go run .`
- Ensure ports 80 and 443 are open; certs are cached in `cert-cache`.

Admin
- Admin portal: `/admin/login`
- Credentials are configured with `ADMIN_USER` and `ADMIN_PASS`.
