# Production scaling profile

For thousands of concurrent users:

- Run 2+ API replicas behind Nginx/ALB.
- Use PostgreSQL 15+ with connection pooling.
- Use Redis 8+ for distributed rate limiting/cache.
- Store scan uploads in object storage when they outgrow the demo 25 MB limit.
- Put TLS termination at the edge and set COOKIE_SECURE=true.
- Add autoscaling based on CPU + request latency.
- Keep API workers stateless except for PostgreSQL/Redis state.
- Route `/api` to the API service and static assets to a CDN if desired.
