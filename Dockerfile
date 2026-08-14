# Ataram Email Analyzer - Frontend Dockerfile
#
# Standalone static-site image. The reference deployment (deploy/) mounts the
# same src/ into an nginx container with deploy/nginx.conf instead; this image
# exists for anyone building the frontend on its own, and must not be the weaker
# of the two.

FROM nginxinc/nginx-unprivileged:1.27-alpine

# The unprivileged image runs as uid 101 and listens on 8080 by default. Copying
# files as root and serving them read-only means a compromised worker cannot
# rewrite the site it serves.
USER root

# Copy frontend files
COPY src/ /usr/share/nginx/html/

# Copy custom nginx configuration (hardened — CSP, HSTS, rate limits)
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Nothing here is ever written at runtime.
RUN chmod -R a-w /usr/share/nginx/html /etc/nginx/conf.d

USER 101

# 8080, not 80: binding a privileged port would require the container to start
# as root.
EXPOSE 8080

# Probes the dedicated liveness path, which is served locally and not proxied.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --quiet --tries=1 --spider http://127.0.0.1:8080/healthz || exit 1

# Start nginx
CMD ["nginx", "-g", "daemon off;"]
