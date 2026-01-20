# Sec-Fetch CSRF Protection

WordPress plugin that provides CSRF protection using the browser's `Sec-Fetch-Site` header, with a fallback to the `Origin` header for older browsers.

## Why?

Traditional WordPress CSRF protection relies on nonces embedded in forms and AJAX requests. This prevents HTML caching because each user needs unique nonce values.

This plugin uses the browser's built-in `Sec-Fetch-Site` header to validate request origin, allowing you to:
- Cache HTML pages (including forms) at the edge
- Eliminate nonce-related cache fragmentation
- Maintain CSRF protection without per-user tokens

## How It Works

1. **Modern browsers** send `Sec-Fetch-Site` header with every request:
   - `same-origin` - Request from same origin (allowed)
   - `same-site` - Request from same site, different subdomain (allowed)
   - `none` - User-initiated navigation (allowed)
   - `cross-site` - Request from different site (blocked for writes)

2. **Older browsers** without `Sec-Fetch-Site` support fall back to `Origin` header validation

3. **Write requests** (POST, PUT, DELETE, etc.) from cross-site origins are blocked

4. **Read requests** (GET, HEAD, OPTIONS) are allowed, except for logged-in users accessing sensitive endpoints

## Installation

1. Upload the plugin to `wp-content/plugins/sec-fetch-csrf`
2. Activate the plugin in WordPress admin

The plugin automatically reorders itself to load first among active plugins, ensuring CSRF protection runs before other plugins process requests.

**Note:** Composer is only required for development and testing. The plugin has no runtime dependencies.

## Configuration

Navigate to **Settings > Sec-Fetch CSRF** in WordPress admin to configure:

- **Bypass patterns** - URL patterns that should skip CSRF validation (e.g., webhook endpoints)
- **Sensitive endpoints** - Endpoints where cross-site GET requests should be blocked for logged-in users
- **Logging** - Enable/disable request logging

## Nonce Behavior

When this plugin is active, WordPress nonce functions are modified:
- `wp_verify_nonce()` always returns `1` (valid) for requests that pass Sec-Fetch validation
- `wp_create_nonce()` returns a static value, enabling HTML caching

This is safe because CSRF protection is handled at the request level before nonces are checked.

## Testing

### Unit Tests (no WordPress required)

```bash
composer install
vendor/bin/pest tests/Unit
```

### E2E Tests (requires running WordPress)

```bash
WP_TEST_URL=https://your-site.test vendor/bin/pest tests/E2E
```

### All Tests

```bash
WP_TEST_URL=https://your-site.test vendor/bin/pest
```

## Browser Support

- **Full support**: All modern browsers (Chrome 76+, Firefox 90+, Safari 16.4+, Edge 79+)
- **Fallback support**: Older browsers via Origin header validation
- **Blocked**: Requests without Sec-Fetch-Site AND without Origin header (likely non-browser clients)

## Requirements

- PHP 8.1+
- WordPress 5.9+

## License

GPL-2.0-or-later

