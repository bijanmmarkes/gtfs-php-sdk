<?php


namespace Trafiklab\Gtfs\Model;


use Composer\CaBundle\CaBundle;
use Exception;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\RequestOptions;
use Psr\Http\Message\ResponseInterface;
use Trafiklab\Gtfs\Model\Files\GtfsAgencyFile;
use Trafiklab\Gtfs\Model\Files\GtfsCalendarDatesFile;
use Trafiklab\Gtfs\Model\Files\GtfsCalendarFile;
use Trafiklab\Gtfs\Model\Files\GtfsDirectionsFile;
use Trafiklab\Gtfs\Model\Files\GtfsFeedInfoFile;
use Trafiklab\Gtfs\Model\Files\GtfsFrequenciesFile;
use Trafiklab\Gtfs\Model\Files\GtfsRoutesFile;
use Trafiklab\Gtfs\Model\Files\GtfsShapesFile;
use Trafiklab\Gtfs\Model\Files\GtfsStopsFile;
use Trafiklab\Gtfs\Model\Files\GtfsStopTimesFile;
use Trafiklab\Gtfs\Model\Files\GtfsTransfersFile;
use Trafiklab\Gtfs\Model\Files\GtfsTripsFile;
use Trafiklab\Gtfs\Util\Internal\AiaCertificateResolver;
use Trafiklab\Gtfs\Util\Internal\ArrayCache;
use ZipArchive;

class GtfsArchive
{
    use ArrayCache;

    private const AGENCY_TXT = "agency.txt";
    private const STOPS_TXT = "stops.txt";
    private const ROUTES_TXT = "routes.txt";
    private const TRIPS_TXT = "trips.txt";
    private const STOP_TIMES_TXT = "stop_times.txt";
    private const CALENDAR_TXT = "calendar.txt";
    private const CALENDAR_DATES_TXT = "calendar_dates.txt";
    private const FARE_ATTRIBUTES_TXT = "fare_attributes.txt"; // Unsupported at this moment
    private const FARE_RULES_TXT = "fare_rules.txt"; // Unsupported at this moment
    private const SHAPES_TXT = "shapes.txt";
    private const FREQUENCIES_TXT = "frequencies.txt"; // Unsupported at this moment
    private const TRANSFERS_TXT = "transfers.txt";
    private const PATHWAYS_TXT = "pathways.txt"; // Unsupported at this moment
    private const LEVELS_TXT = "levels.txt"; // Unsupported at this moment
    private const FEED_INFO_TXT = "feed_info.txt";
    private const DIRECTIONS_TXT = "directions.txt"; // Experimental GTFS+ feed.

    private const TEMP_ROOT = "/tmp/gtfs/";

    private $fileRoot;

    /** @link https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Last-Modified */
    private const LAST_MODIFIED_FORMAT = "D, d M Y H:i:s e";
    /** @var null|string $archiveLastModified */
    private static $archiveLastModified = null;
    /** @var null|string $archiveETag */
    private static $archiveETag = null;

    private function __construct(string $fileRoot)
    {
        $this->fileRoot = $fileRoot;
    }

    /**
     * Download a GTFS zipfile.
     *
     * @param string $url The URL that points to the archive.
     *
     * @return GtfsArchive The downloaded archive.
     * @throws Exception
     */
    public static function createFromUrl(string $url): GtfsArchive
    {
        $downloadedArchive = self::downloadFile($url);
        $fileRoot = self::extractFiles($downloadedArchive, true);
        return new GtfsArchive($fileRoot);
    }

    /**
     * Build a Guzzle client with sensible defaults for downloading GTFS archives.
     *
     * The CA bundle comes from composer/ca-bundle (Mozilla NSS roots) so
     * behavior is consistent across environments regardless of php.ini's
     * openssl.cafile.
     *
     * Some GTFS hosts serve incomplete certificate chains (the leaf cert
     * but not the intermediate that signs it). Browsers and the curl
     * binary work around this via "AIA chasing" — fetching the missing
     * intermediate from the URL embedded in the leaf cert. PHP's curl-
     * with-OpenSSL does not. {@see executeWithAiaFallback()} retries any
     * request that fails verification with an augmented CA bundle built
     * by {@see AiaCertificateResolver}, so this works automatically for
     * any host whose cert has a valid AIA extension.
     *
     * @param string|null $caBundleOverride Per-host CA bundle to use for
     *     this client instance (used by the AIA retry path). Null means
     *     "use the system default".
     */
    private static function createHttpClient(?string $caBundleOverride = null): Client
    {
        return new Client([
            RequestOptions::TIMEOUT         => 120,
            RequestOptions::CONNECT_TIMEOUT => 15,
            RequestOptions::HTTP_ERRORS     => false, // we want to inspect 304/4xx ourselves
            RequestOptions::VERIFY          => $caBundleOverride ?? CaBundle::getSystemCaRootBundlePath(),
            RequestOptions::HEADERS         => [
                'User-Agent' => 'trafiklab/gtfs-php-sdk',
            ],
        ]);
    }

    /**
     * Execute a Guzzle GET request, transparently retrying once with an
     * AIA-augmented CA bundle if the first attempt fails TLS verification.
     *
     * This is the seam where AIA chasing happens — keeping it here means
     * both download paths (createFromUrl + createFromUrlIfModified) get
     * the workaround for free with no per-call boilerplate.
     *
     * Behavior:
     *  - If the host has previously needed AIA chasing (we have a cached
     *    bundle for it), use that bundle directly — no failing first
     *    attempt. Saves ~1s per request on known-broken hosts.
     *  - Otherwise try with the default system bundle first.
     *  - Verification failures (cURL errno 60 OR 77) trigger one retry
     *    with intermediates fetched from the host's AIA URL.
     *  - All other errors propagate untouched.
     *  - If the AIA discovery itself fails (no AIA URL, fetch failure,
     *    etc.) we re-throw the ORIGINAL verification error so the caller
     *    sees the real problem rather than a confusing AIA error.
     *
     * @param array<string, mixed> $options Guzzle request options (sink, headers, etc.).
     * @throws GuzzleException
     */
    private static function executeWithAiaFallback(string $url, array $options): ResponseInterface
    {
        // Fast path: if we already have AIA-discovered intermediates cached
        // for this host, use the augmented bundle directly. AiaCertificateResolver
        // returns a cached path without re-running the TLS probe.
        $systemBundle = CaBundle::getSystemCaRootBundlePath();
        $cachedBundle = AiaCertificateResolver::getCachedBundleForHost($url, $systemBundle);
        if ($cachedBundle !== null) {
            return self::createHttpClient($cachedBundle)->request('GET', $url, $options);
        }

        try {
            return self::createHttpClient()->request('GET', $url, $options);
        } catch (ConnectException | RequestException $exception) {
            if (!self::isTlsVerifyFailure($exception)) {
                throw $exception;
            }

            $augmentedBundle = AiaCertificateResolver::buildAugmentedBundle($url, $systemBundle);

            if ($augmentedBundle === null) {
                // AIA chasing didn't help (no AIA URL, fetch failed, etc.).
                // Re-throw the ORIGINAL verify error rather than masking it.
                throw $exception;
            }

            return self::createHttpClient($augmentedBundle)->request('GET', $url, $options);
        }
    }

    /**
     * Detects the curl error codes that indicate a TLS verification failure
     * worth attempting AIA chasing for:
     *
     *   60 = CURLE_SSL_CACERT — peer cert can't be authenticated with the
     *        given CA cert(s). The classic missing-intermediate symptom.
     *   77 = CURLE_SSL_CACERT_BADFILE — problem reading the CA bundle.
     *        Less likely AIA-fixable but harmless to try.
     */
    private static function isTlsVerifyFailure(GuzzleException $exception): bool
    {
        if (!$exception instanceof ConnectException && !$exception instanceof RequestException) {
            return false;
        }
        $context = $exception->getHandlerContext();
        $errno   = $context['errno'] ?? null;
        if ($errno === 60 || $errno === 77) {
            return true;
        }
        // Some Guzzle versions surface only the message; fall back to a
        // string match for the most common cases.
        $message = $exception->getMessage();
        return str_contains($message, 'cURL error 60')
            || str_contains($message, 'unable to get local issuer certificate')
            || str_contains($message, 'certificate verify failed');
    }

    /**
     * Check if the temp directory exists, if not create it.
     */
    private static function makeTempDir()
    {
        if (!file_exists(self::TEMP_ROOT)) {
            mkdir(self::TEMP_ROOT, 0777, true);
        }
    }

    /**
     * Only create a new Archive if it has been modified since the last PULL.
     * We delete the Zip archive after each cycle as this is meant to constantly
     * check headers.
     *
     * Sends If-Modified-Since (when $lastModified is provided) and treats a
     * 304 response as "no change". Returns null on 304; throws on non-2xx.
     *
     * @param string $url
     * @param \DateTime|null $lastModified
     * @param string|null $eTag
     * @return GtfsArchive|null
     * @throws Exception
     */
    public static function createFromUrlIfModified(
        string $url,
        ?\DateTime $lastModified = null,
        ?string $eTag = null
    ): ?GtfsArchive {
        $temp_file = self::TEMP_ROOT . md5($url) . ".zip";
        if (file_exists($temp_file)) {
            // Another concurrent caller is mid-download (or a prior run crashed
            // before cleanup). Bail rather than racing.
            return null;
        }

        // Track the IMS string for getArchiveLastModified() consumers — set even
        // on the early-return paths (matches legacy behavior).
        self::$archiveLastModified = $lastModified !== null
            ? self::getLastModifiedFromDateTime($lastModified)
            : '';

        try {
            self::makeTempDir();

            $headers = [];
            if ($lastModified !== null) {
                $headers['If-Modified-Since'] = self::$archiveLastModified;
            }
            // Note: we intentionally do NOT send If-None-Match here. The original
            // implementation also did not — it compared the response ETag against
            // the caller-supplied $eTag client-side. Preserving that contract.

            $response = self::executeWithAiaFallback($url, [
                RequestOptions::HEADERS => $headers,
                RequestOptions::SINK    => $temp_file,
            ]);

            $statusCode = $response->getStatusCode();
            switch ($statusCode) {
                case 200:
                    self::$archiveLastModified = $response->getHeaderLine('Last-Modified') ?: null;
                    self::$archiveETag         = $response->getHeaderLine('ETag') ?: null;

                    // Match the original quirky semantics: if the caller didn't
                    // know a Last-Modified date but did know an ETag, and the
                    // server returned the same ETag, treat it as "unchanged"
                    // even though the server returned 200. (Some hosts ignore
                    // If-None-Match but the ETag tells us nothing changed.)
                    if (
                        $lastModified === null
                        && $eTag !== null
                        && self::$archiveETag !== null
                        && $eTag === self::$archiveETag
                    ) {
                        return null;
                    }

                    $fileRoot = self::extractFiles($temp_file, true);
                    return new GtfsArchive($fileRoot);

                case 304:
                    // Not modified. Echo the caller-supplied ETag back so
                    // getArchiveETag() stays consistent.
                    self::$archiveETag = $eTag;
                    return null;

                default:
                    throw new Exception("Could not open the GTFS archive, Status Code: {$statusCode}");
            }
        } catch (GuzzleException $exception) {
            throw new Exception(
                "There was an issue downloading the GTFS from the requested URL: {$url}, Error: " .
                $exception->getMessage(),
                0,
                $exception
            );
        } finally {
            // Clean up the on-disk zip if it survived past extraction (or if we
            // failed before extracting).
            self::deleteArchive($temp_file);
        }
    }

    /**
     * Open a local GTFS zipfile.
     *
     * @param string $path The path that points to the archive.
     *
     * @return GtfsArchive The downloaded archive.
     * @throws Exception
     */
    public static function createFromPath(string $path): GtfsArchive
    {
        $fileRoot = self::extractFiles($path);
        return new GtfsArchive($fileRoot);
    }

    /**
     * Download the latest GTFS archive to a temp file. No conditional-request
     * semantics — used by createFromUrl().
     *
     * @throws Exception
     */
    private static function downloadFile(string $url): string
    {
        $temp_file = self::TEMP_ROOT . md5($url) . ".zip";

        if (!file_exists($temp_file)) {
            self::makeTempDir();
            try {
                $response = self::executeWithAiaFallback($url, [
                    RequestOptions::SINK => $temp_file,
                ]);
                if ($response->getStatusCode() !== 200) {
                    throw new Exception(
                        "Could not download GTFS archive from {$url}, Status Code: " .
                        $response->getStatusCode()
                    );
                }
            } catch (GuzzleException $exception) {
                throw new Exception(
                    "There was an issue downloading the GTFS from the requested URL: {$url}, Error: " .
                    $exception->getMessage(),
                    0,
                    $exception
                );
            }
        }

        return $temp_file;
    }

    /**
     * @throws Exception
     */
    private static function extractFiles(string $archiveFilePath, bool $deleteArchive = false)
    {
        // Load the zip file.
        $zip = new ZipArchive();
        if ($zip->open($archiveFilePath) != 'true') {
            throw new Exception('Could not open the GTFS archive');
        }
        // Extract the zip file and remove it.
        $extractionPath = substr($archiveFilePath, 0, strlen($archiveFilePath) - 4) . '/';
        $zip->extractTo($extractionPath);
        $zip->close();

        if ($deleteArchive) {
            self::deleteArchive($archiveFilePath);
        }

        return $extractionPath;
    }

    /**
     * @return GtfsAgencyFile
     */
    public function getAgencyFile(): GtfsAgencyFile
    {
        return $this->loadGtfsFileThroughCache(__METHOD__, self::AGENCY_TXT, GtfsAgencyFile::class);
    }

    /**
     * @return GtfsCalendarDatesFile
     */
    public function getCalendarDatesFile(): GtfsCalendarDatesFile
    {
        return $this->loadGtfsFileThroughCache(__METHOD__, self::CALENDAR_DATES_TXT, GtfsCalendarDatesFile::class);
    }

    /**
     * @return GtfsCalendarFile
     */
    public function getCalendarFile(): GtfsCalendarFile
    {
        return $this->loadGtfsFileThroughCache(__METHOD__, self::CALENDAR_TXT, GtfsCalendarFile::class);
    }

    /**
     * @return GtfsFeedInfoFile
     */
    public function getFeedInfoFile(): GtfsFeedInfoFile
    {
        return $this->loadGtfsFileThroughCache(__METHOD__, self::FEED_INFO_TXT, GtfsFeedInfoFile::class);
    }

    /**
     * @return GtfsRoutesFile
     */
    public function getRoutesFile(): GtfsRoutesFile
    {
        return $this->loadGtfsFileThroughCache(__METHOD__, self::ROUTES_TXT, GtfsRoutesFile::class);
    }

    /**
     * @return GtfsShapesFile
     */
    public function getShapesFile(): GtfsShapesFile
    {
        return $this->loadGtfsFileThroughCache(__METHOD__, self::SHAPES_TXT, GtfsShapesFile::class);
    }

    /**
     * @return GtfsStopsFile
     */
    public function getStopsFile(): GtfsStopsFile
    {
        return $this->loadGtfsFileThroughCache(__METHOD__, self::STOPS_TXT, GtfsStopsFile::class);
    }

    /**
     * @return GtfsStopTimesFile
     */
    public function getStopTimesFile(): GtfsStopTimesFile
    {
        return $this->loadGtfsFileThroughCache(__METHOD__, self::STOP_TIMES_TXT, GtfsStopTimesFile::class);
    }

    /**
     * @return GtfsTransfersFile
     */
    public function getTransfersFile(): GtfsTransfersFile
    {
        return $this->loadGtfsFileThroughCache(__METHOD__, self::TRANSFERS_TXT, GtfsTransfersFile::class);
    }

    /**
     * @return GtfsTripsFile
     */
    public function getTripsFile(): GtfsTripsFile
    {
        return $this->loadGtfsFileThroughCache(__METHOD__, self::TRIPS_TXT, GtfsTripsFile::class);
    }

    /**
     * @return GtfsFrequenciesFile
     */
    public function getFrequenciesFile(): GtfsFrequenciesFile
    {
        return $this->loadGtfsFileThroughCache(__METHOD__, self::FREQUENCIES_TXT, GtfsFrequenciesFile::class);
    }
    /**
     * @return GtfsDirectionsFile|null
     */
    public function getDirectionsFile(): ?GtfsDirectionsFile
    {
        return $this->loadGtfsFileThroughCache(__METHOD__, self::DIRECTIONS_TXT, GtfsDirectionsFile::class);
    }

    /**
     * Delete the uncompressed files. This should be done as a cleanup when you're ready.
     */
    public function deleteUncompressedFiles()
    {
        // Remove temporary data.
        if (!file_exists($this->fileRoot)) {
            return;
        }
        $files = scandir($this->fileRoot);
        foreach ($files as $file) {
            if ($file != '.' && $file != '..') {
                $path = $this->fileRoot . DIRECTORY_SEPARATOR . $file;
                /** Check for OS Specific directories that could've been added. Ex: _MACOSX/ */
                if (is_dir($path)) {
                    rmdir($path);
                } else {
                    // Remove all extracted files from the zip file.
                    unlink($path);
                }

            }
        }
        reset($files);
        // Remove the empty folder.
        rmdir($this->fileRoot);
    }

    private static function deleteArchive(string $archiveFilePath)
    {
        if (file_exists($archiveFilePath)) {
            unlink($archiveFilePath);
        }
    }

    private function loadGtfsFileThroughCache(string $method, string $file, string $class)
    {
        if ($this->getCachedResult($method) == null) {
            $this->setCachedResult($method, new $class($this, $this->fileRoot . $file));
        }
        return $this->getCachedResult($method);
    }

    /**
     * Return the DateTime Object for the Last Modified Date
     * Useful for storing in databases, etc.
     * @return \DateTime|null
     * @throws Exception
     */
    public function getLastModifiedDateTime(): ?\DateTime
    {
        if (self::$archiveLastModified !== null) {
            return (
                new \DateTime(
                    self::$archiveLastModified,
                    new \DateTimeZone('GMT')
                )
            );
        }
        return null;
    }

    /**
     * @link https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Last-Modified
     * @param \DateTime $dateTime
     * @return string
     */
    public static function getLastModifiedFromDateTime(\DateTime $dateTime): string
    {
        return $dateTime
            ->setTimezone(new \DateTimeZone('GMT'))
            ->format(self::LAST_MODIFIED_FORMAT);
    }

    /**
     * @return string|null
     */
    public function getArchiveLastModified(): ?string
    {
        return self::$archiveLastModified ?? null;
    }

    /**
     * @return string|null
     */
    public function getArchiveETag(): ?string
    {
        return self::$archiveETag ?? null;
    }
}
