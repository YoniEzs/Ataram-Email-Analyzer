# Ataram Email Analyzer - Frontend Dockerfile

# Pinned by digest for reproducible, tamper-resistant builds.
# Dependabot (docker ecosystem) keeps this digest updated.
FROM nginx:alpine@sha256:7068961d45b07b2af510ac002e9daa63a1d3eba2111202d6768798690800fffd

# Keep the pinned base identity while applying security fixes published to
# its Alpine release channel. The signed release-image digest is the exact
# deployable artifact.
RUN apk upgrade --no-cache

# Copy frontend files
COPY src/ /usr/share/nginx/html/

# Copy custom nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Expose port
EXPOSE 80

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --quiet --tries=1 --spider http://localhost/frontend-health || exit 1

# Start nginx
CMD ["nginx", "-g", "daemon off;"]
