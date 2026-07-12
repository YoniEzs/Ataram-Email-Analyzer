# Ataram Email Analyzer - Frontend Dockerfile

# Pinned by digest for reproducible, tamper-resistant builds.
# Dependabot (docker ecosystem) keeps this digest updated.
FROM nginx:alpine@sha256:54f2a904c251d5a34adf545a72d32515a15e08418dae0266e23be2e18c66fefa

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
