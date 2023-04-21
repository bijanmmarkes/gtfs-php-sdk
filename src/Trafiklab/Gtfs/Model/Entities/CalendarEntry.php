<?php


namespace Trafiklab\Gtfs\Model\Entities;


use DateTime;
use Trafiklab\Gtfs\Model\GtfsArchive;

class CalendarEntry
{

    private $service_id;
    private $monday;
    private $tuesday;
    private $wednesday;
    private $thursday;
    private $friday;
    private $saturday;
    private $sunday;
    private $start_date;
    private $end_date;
    private $archive;

    /**
     * CalendarEntry constructor.
     *
     * @param GtfsArchive $archive The archive in which this data originates, used to link between files.
     * @param array       $data    An associative array containing the variable values.
     *
     * @internal Not to be used outside of the Trafiklab\Gtfs\Model package.
     */
    function __construct(GtfsArchive $archive, array $data)
    {
        foreach ($data as $variable => $value) {
            $this->$variable = $value;
        }
        $this->archive = $archive;
    }

    /**
     * @return mixed
     */
    public function getServiceId()
    {
        return $this->service_id;
    }

    /**
     * @return int
     */
    public function getMonday(): int
    {
        return $this->monday;
    }

    /**
     * @return int
     */
    public function getTuesday(): int
    {
        return $this->tuesday;
    }

    /**
     * @return int
     */
    public function getWednesday(): int
    {
        return $this->wednesday;
    }

    /**
     * @return int
     */
    public function getThursday(): int
    {
        return $this->thursday;
    }

    /**
     * @return int
     */
    public function getFriday(): int
    {
        return $this->friday;
    }

    /**
     * @return int
     */
    public function getSaturday(): int
    {
        return $this->saturday;
    }

    /**
     * @return int
     */
    public function getSunday(): int
    {
        return $this->sunday;
    }

    /**
     * @return DateTime
     */
    public function getStartDate(): DateTime
    {
        return DateTime::createFromFormat("Ymd", $this->start_date);
    }

    /**
     * @return DateTime
     */
    public function getEndDate(): DateTime
    {
        return DateTime::createFromFormat("Ymd", $this->end_date);
    }

}
