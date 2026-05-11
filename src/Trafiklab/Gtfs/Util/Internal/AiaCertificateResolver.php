<?php

namespace Trafiklab\Gtfs\Util\Internal;

use Composer\CaBundle\CaBundle;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\RequestOptions;
use Throwable;

/**
 * Internal helper that performs "AIA chasing" — fetching the missing
 * intermediate certificate(s) for a host that serves an incomplete TLS
 * chain, so we can verify the chain without weakening security.
 *
 * Browsers and the curl binary (when linked against SecureTransport or
 * NSS) do this transparently. The curl-with-OpenSSL stack that ships
 * with most PHP builds does not, which is why GTFS hosts like NFTA
 * (which serves only the leaf + cross-signed root, omitting the
 * Sectigo intermediate) fail to verify out of the box.
 *
 * This class is intentionally side-effect-free except for writing
 * resolved intermediates to a per-host cache file in the system temp
 * directory, so the AIA discovery only runs once per host per
 * machine for the certificate's lifetime.
 *
 * @internal Not part of the public API. May change without notice.
 */
final class AiaCertificateResolver
{
    /**
     * Hard cap on intermediates we'll chase per host. A real-world chain
     * almost never exceeds 3 (leaf → intermediate → cross-signed root),
     * so 5 leaves comfortable headroom while preventing pathological
     * loops if a misconfigured CA points at itself.
     */
    private const MAX_CHAIN_DEPTH = 5;

    /** Connection timeout for the TLS probe + intermediate downloads (seconds). */
    private const FETCH_TIMEOUT = 10;

    /**
     * Returns the path to a previously built augmented bundle for this host
     * if one exists in the cache, or null otherwise. Used by callers as a
     * fast path to skip the failing-first-attempt + retry dance when we
     * already know the host needs AIA chasing.
     *
     * Does NOT do any network I/O — purely a disk lookup.
     */
    public static function getCachedBundleForHost(string $url, string $systemBundlePath): ?string
    {
        $host = parse_url($url, PHP_URL_HOST);
        $port = parse_url($url, PHP_URL_PORT) ?: 443;
        if (!is_string($host) || $host === '') {
            return null;
        }

        $aiaCachePath = sys_get_temp_dir()
            . '/gtfs-php-sdk-aia-' . substr(sha1($host . ':' . $port), 0, 16) . '.pem';

        $intermediates = self::loadCachedIntermediates($aiaCachePath);
        if ($intermediates === null || $intermediates === []) {
            return null;
        }

        $systemContents = @file_get_contents($systemBundlePath);
        if ($systemContents === false) {
            return null;
        }
        $merged     = $systemContents . "\n" . implode("\n", $intermediates);
        $mergedPath = sys_get_temp_dir()
            . '/gtfs-php-sdk-bundle-' . substr(sha1($host . ':' . $port . $merged), 0, 16) . '.pem';
        if (file_exists($mergedPath)) {
            return $mergedPath;
        }
        if (@file_put_contents($mergedPath, $merged) === false) {
            return null;
        }
        return $mergedPath;
    }

    /**
     * Attempt to resolve and cache the intermediate chain for a host so
     * subsequent TLS verifications can succeed.
     *
     * Returns the path to a per-host CA bundle (system roots + the freshly
     * fetched intermediates) on success, or null if AIA chasing didn't
     * produce a usable result. Callers should treat null as "we tried, it
     * didn't work" and surface the original verify error.
     *
     * @param string $url        Full URL of the request that failed verification.
     * @param string $systemBundlePath Path to the trusted root CA bundle to merge with.
     */
    public static function buildAugmentedBundle(string $url, string $systemBundlePath): ?string
    {
        $host = parse_url($url, PHP_URL_HOST);
        $port = parse_url($url, PHP_URL_PORT) ?: 443;
        if (!is_string($host) || $host === '') {
            return null;
        }

        // Per-host cache so we don't re-do the TLS probe + AIA fetch on
        // every request. Keyed by host:port. We do NOT key by cert
        // fingerprint — when the cert rotates, the cached intermediates
        // either still apply (most likely) or the verify will fail again
        // and we'll re-resolve. Trade-off: cheap cache, mild waste.
        $cachePath = sys_get_temp_dir()
            . '/gtfs-php-sdk-aia-' . substr(sha1($host . ':' . $port), 0, 16) . '.pem';

        $intermediates = self::loadCachedIntermediates($cachePath);
        if ($intermediates === null) {
            // Cache miss — discover via TLS probe + AIA fetch.
            $intermediates = self::discoverIntermediates($host, (int) $port);
            if ($intermediates === []) {
                return null;
            }
            // Best-effort write; a read-only filesystem just means we
            // re-discover on the next call — still correct, just slower.
            @file_put_contents($cachePath, implode("\n", $intermediates));
        }

        // Build the merged "system roots + per-host intermediates" bundle.
        $systemContents = @file_get_contents($systemBundlePath);
        if ($systemContents === false) {
            return null;
        }
        $merged       = $systemContents . "\n" . implode("\n", $intermediates);
        $mergedPath   = sys_get_temp_dir()
            . '/gtfs-php-sdk-bundle-' . substr(sha1($host . ':' . $port . $merged), 0, 16) . '.pem';
        if (!file_exists($mergedPath)) {
            if (@file_put_contents($mergedPath, $merged) === false) {
                return null;
            }
        }
        return $mergedPath;
    }

    /**
     * Load previously discovered intermediates for a host. Returns null on
     * cache miss; returns an array (possibly empty) on hit.
     *
     * @return list<string>|null
     */
    private static function loadCachedIntermediates(string $cachePath): ?array
    {
        if (!file_exists($cachePath)) {
            return null;
        }
        $contents = @file_get_contents($cachePath);
        if ($contents === false || trim($contents) === '') {
            return [];
        }
        // Split on the PEM boundary; preserve the BEGIN line.
        $blocks = preg_split('/(?=-----BEGIN CERTIFICATE-----)/', $contents, -1, PREG_SPLIT_NO_EMPTY);
        return $blocks === false ? [] : array_values(array_filter(array_map('trim', $blocks)));
    }

    /**
     * Open a TLS connection to the host (with verification disabled — we are
     * only inspecting the served chain, not trusting it for data exchange),
     * pull the leaf certificate, and walk its AIA "CA Issuers" URL until we
     * either reach a self-signed cert or hit MAX_CHAIN_DEPTH.
     *
     * @return list<string> Array of PEM-encoded intermediate certificates,
     *                      ordered leaf-issuer first, root last. Empty on failure.
     */
    private static function discoverIntermediates(string $host, int $port): array
    {
        $leaf = self::probeLeafCertificate($host, $port);
        if ($leaf === null) {
            return [];
        }

        $intermediates = [];
        $currentCert   = $leaf;
        $http          = self::createBootstrapClient();

        for ($i = 0; $i < self::MAX_CHAIN_DEPTH; $i++) {
            $aiaUrl = self::extractAiaUrl($currentCert);
            if ($aiaUrl === null) {
                break;
            }

            $issuerPem = self::fetchCertificateAsPem($http, $aiaUrl);
            if ($issuerPem === null) {
                break;
            }

            $intermediates[] = $issuerPem;

            // If the freshly fetched cert is self-signed, we've reached a
            // root and can stop. Roots should not need to be in our bundle
            // (they're already in the system store) but keeping them is
            // harmless and avoids a separate self-signed probe.
            if (self::isSelfSigned($issuerPem)) {
                break;
            }

            $currentCert = $issuerPem;
        }

        return $intermediates;
    }

    /**
     * Open a TLS connection with peer verification DISABLED, capture the
     * cert chain, and return the leaf as a PEM string.
     *
     * Disabling verification here is safe: we never read or write
     * application data over this socket. We only care about what cert
     * the server presents so we can chase its issuer.
     */
    private static function probeLeafCertificate(string $host, int $port): ?string
    {
        $context = stream_context_create([
            'ssl' => [
                'verify_peer'             => false,
                'verify_peer_name'        => false,
                'capture_peer_cert'       => true,
                'capture_peer_cert_chain' => true,
                'SNI_enabled'             => true,
                'peer_name'               => $host,
            ],
        ]);

        $errno  = 0;
        $errstr = '';
        $client = @stream_socket_client(
            "ssl://{$host}:{$port}",
            $errno,
            $errstr,
            self::FETCH_TIMEOUT,
            STREAM_CLIENT_CONNECT,
            $context
        );

        if ($client === false) {
            return null;
        }

        try {
            $params = stream_context_get_params($client);
            $cert   = $params['options']['ssl']['peer_certificate'] ?? null;
            if ($cert === null) {
                return null;
            }
            $pem = '';
            if (!openssl_x509_export($cert, $pem)) {
                return null;
            }
            return $pem;
        } finally {
            fclose($client);
        }
    }

    /**
     * Read the "CA Issuers" URL from the cert's Authority Information Access
     * extension. Returns null if the extension is absent or unparseable.
     *
     * We only honor http(s) URLs — some legacy AIA extensions list LDAP
     * URIs which we can't (and don't want to) follow.
     */
    private static function extractAiaUrl(string $pem): ?string
    {
        $parsed = @openssl_x509_parse($pem, true);
        if (!is_array($parsed) || !isset($parsed['extensions']['authorityInfoAccess'])) {
            return null;
        }

        $aia = $parsed['extensions']['authorityInfoAccess'];
        // The extension is rendered as a multi-line string like:
        //   CA Issuers - URI:http://crt.sectigo.com/...crt
        //   OCSP - URI:http://ocsp.sectigo.com
        if (preg_match('/CA Issuers - URI:(\S+)/i', $aia, $match)) {
            $url = $match[1];
            if (str_starts_with($url, 'http://') || str_starts_with($url, 'https://')) {
                return $url;
            }
        }
        return null;
    }

    /**
     * Fetch a certificate (DER or PEM) from an AIA URL and return it as PEM.
     * Returns null on any failure — callers fall back to whatever they had.
     */
    private static function fetchCertificateAsPem(Client $client, string $url): ?string
    {
        try {
            $response = $client->request('GET', $url);
        } catch (GuzzleException | Throwable) {
            return null;
        }

        if ($response->getStatusCode() !== 200) {
            return null;
        }

        $body = (string) $response->getBody();
        if ($body === '') {
            return null;
        }

        // PEM (text) and DER (binary) are both common AIA payloads.
        if (str_contains($body, '-----BEGIN CERTIFICATE-----')) {
            return trim($body);
        }

        // DER → PEM. openssl_x509_export refuses raw DER bytes (it needs a
        // parsed cert resource), so we hand-wrap: base64-encode the DER
        // payload at 64-char line breaks and bracket with the PEM markers.
        $pem = "-----BEGIN CERTIFICATE-----\n"
            . chunk_split(base64_encode($body), 64, "\n")
            . "-----END CERTIFICATE-----\n";

        // Validate the result actually parses; if not, the body might be a
        // PKCS#7 bundle (.p7c / .p7b) — try unwrapping that instead.
        if (@openssl_x509_parse($pem, false) !== false) {
            return $pem;
        }
        return self::extractFromPkcs7($body);
    }

    /**
     * Some CAs serve their AIA URL as a PKCS#7 (.p7c / .p7b) bundle rather
     * than a bare DER cert. Best-effort unwrap.
     */
    private static function extractFromPkcs7(string $derBody): ?string
    {
        $tempIn  = tempnam(sys_get_temp_dir(), 'aia-p7-');
        $tempOut = tempnam(sys_get_temp_dir(), 'aia-p7-out-');
        if ($tempIn === false || $tempOut === false) {
            return null;
        }
        try {
            file_put_contents($tempIn, $derBody);
            // pkcs7_read writes its output as a PEM bundle; the first cert
            // is what we want (the issuer for our leaf).
            $signers = [];
            if (!@openssl_pkcs7_read("file://{$tempIn}", $signers)) {
                return null;
            }
            return is_array($signers) && isset($signers[0]) ? trim($signers[0]) : null;
        } finally {
            @unlink($tempIn);
            @unlink($tempOut);
        }
    }

    /**
     * A cert is self-signed when its subject equals its issuer. Used as the
     * stop condition for the AIA walk so we don't keep fetching past a root.
     */
    private static function isSelfSigned(string $pem): bool
    {
        $parsed = @openssl_x509_parse($pem, false);
        if (!is_array($parsed)) {
            return false;
        }
        $subject = $parsed['name'] ?? null;
        $issuer  = isset($parsed['issuer']) && is_array($parsed['issuer'])
            ? '/' . implode('/', array_map(
                static fn ($k, $v) => "{$k}={$v}",
                array_keys($parsed['issuer']),
                array_values($parsed['issuer'])
            ))
            : null;
        return $subject !== null && $issuer !== null && $subject === $issuer;
    }

    /**
     * A bare-bones Guzzle client used only for fetching intermediates from
     * AIA URLs. AIA URLs are nearly always plain http (the CA/B Forum
     * forbids HTTPS for them to avoid bootstrap chicken-and-egg) so the
     * verify path here is mostly moot, but we still point it at the system
     * bundle for the rare case a CA serves AIA over HTTPS.
     */
    private static function createBootstrapClient(): Client
    {
        return new Client([
            RequestOptions::TIMEOUT         => self::FETCH_TIMEOUT,
            RequestOptions::CONNECT_TIMEOUT => self::FETCH_TIMEOUT,
            RequestOptions::HTTP_ERRORS     => false,
            RequestOptions::VERIFY          => CaBundle::getSystemCaRootBundlePath(),
            RequestOptions::HEADERS         => [
                'User-Agent' => 'trafiklab/gtfs-php-sdk (AIA)',
            ],
        ]);
    }
}
