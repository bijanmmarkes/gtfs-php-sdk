<?php


namespace Trafiklab\Gtfs\Model;


class GtfsRouteType
{
    const ROUTE_TYPES = [
        '0' => 'Tram, streetcar, or light rail',
        '1' => 'Subway or metro',
        '2' => 'Rail',
        '3' => 'Bus',
        '4' => 'Ferry',
        '5' => 'Cable car',
        '6' => 'Gondola or suspended cable car',
        '7' => 'Funicular',
        '100' => 'Railway Service',
        '101' => 'High Speed Rail Service',
        '102' => 'Long Distance Trains',
        '103' => 'Inter Regional Rail Service',
        '104' => 'Car Transport Rail Service',
        '105' => 'Sleeper Rail Service',
        '106' => 'Regional Rail Service',
        '107' => 'Tourist Railway Service',
        '108' => 'Rail Shuttle (Within Complex)',
        '109' => 'Suburban Railway',
        '110' => 'Replacement Rail Service',
        '111' => 'Special Rail Service',
        '112' => 'Lorry Transport Rail Service',
        '113' => 'All Rail Services',
        '114' => 'Cross-Country Rail Service',
        '115' => 'Vehicle Transport Rail Service',
        '116' => 'Rack and Pinion Railway',
        '117' => 'Additional Rail Service',
        '200' => 'Coach Service',
        '201' => 'International Coach Service',
        '202' => 'National Coach Service',
        '203' => 'Shuttle Coach Service',
        '204' => 'Regional Coach Service',
        '205' => 'Special Coach Service',
        '206' => 'Sightseeing Coach Service',
        '207' => 'Tourist Coach Service',
        '208' => 'Commuter Coach Service',
        '209' => 'All Coach Services',
        '300' => 'Suburban Railway Service',
        '400' => 'Urban Railway Service',
        '401' => 'Metro Service',
        '402' => 'Underground Service',
        '403' => 'Urban Railway Service',
        '404' => 'All Urban Railway Services',
        '405' => 'Monorail',
        '500' => 'Metro Service',
        '600' => 'Underground Service',
        '700' => 'Bus Service',
        '701' => 'Regional Bus Service',
        '702' => 'Express Bus Service',
        '703' => 'Stopping Bus Service',
        '704' => 'Local Bus Service',
        '705' => 'Night Bus Service',
        '706' => 'Post Bus Service',
        '707' => 'Special Needs Bus',
        '708' => 'Mobility Bus Service',
        '709' => 'Mobility Bus for Registered Disabled',
        '710' => 'Sightseeing Bus',
        '711' => 'Shuttle Bus',
        '712' => 'School Bus',
        '713' => 'School and Public Service Bus',
        '714' => 'Rail Replacement Bus Service',
        '715' => 'Demand and Response Bus Service',
        '716' => 'All Bus Services',
        '800' => 'Trolleybus Service',
        '900' => 'Tram Service',
        '901' => 'City Tram Service',
        '902' => 'Local Tram Service',
        '903' => 'Regional Tram Service',
        '904' => 'Sightseeing Tram Service',
        '905' => 'Shuttle Tram Service',
        '906' => 'All Tram Services',
        '1000' => 'Water Transport Service',
        '1001' => 'International Car Ferry Service',
        '1002' => 'National Car Ferry Service',
        '1003' => 'Regional Car Ferry Service',
        '1004' => 'Local Car Ferry Service',
        '1005' => 'International Passenger Ferry Service',
        '1006' => 'National Passenger Ferry Service',
        '1007' => 'Regional Passenger Ferry Service',
        '1008' => 'Local Passenger Ferry Service',
        '1009' => 'Post Boat Service',
        '1010' => 'Train Ferry Service',
        '1011' => 'Road-Link Ferry Service',
        '1012' => 'Airport-Link Ferry Service',
        '1013' => 'Car High-Speed Ferry Service',
        '1014' => 'Passenger High-Speed Ferry Service',
        '1015' => 'Sightseeing Boat Service',
        '1016' => 'School Boat',
        '1017' => 'Cable-Drawn Boat Service',
        '1018' => 'River Bus Service',
        '1019' => 'Scheduled Ferry Service',
        '1020' => 'Shuttle Ferry Service',
        '1021' => 'All Water Transport Services',
        '1100' => 'Air Service',
        '1101' => 'International Air Service',
        '1102' => 'Domestic Air Service',
        '1103' => 'Intercontinental Air Service',
        '1104' => 'Domestic Scheduled Air Service',
        '1105' => 'Shuttle Air Service',
        '1106' => 'Intercontinental Charter Air Service',
        '1107' => 'International Charter Air Service',
        '1108' => 'Round-Trip Charter Air Service',
        '1109' => 'Sightseeing Air Service',
        '1110' => 'Helicopter Air Service',
        '1111' => 'Domestic Charter Air Service',
        '1112' => 'Schengen-Area Air Service',
        '1113' => 'Airship Service',
        '1114' => 'All Air Services',
        '1200' => 'Ferry Service',
        '1300' => 'Telecabin Service',
        '1301' => 'Telecabin Service',
        '1302' => 'Cable Car Service',
        '1303' => 'Elevator Service',
        '1304' => 'Chair Lift Service',
        '1305' => 'Drag Lift Service',
        '1306' => 'Small Telecabin Service',
        '1307' => 'All Telecabin Services',
        '1400' => 'Funicular Service',
        '1401' => 'Funicular Service',
        '1402' => 'All Funicular Service',
        '1500' => 'Taxi Service',
        '1501' => 'Communal Taxi Service',
        '1502' => 'Water Taxi Service',
        '1503' => 'Rail Taxi Service',
        '1504' => 'Bike Taxi Service',
        '1505' => 'Licensed Taxi Service',
        '1506' => 'Private Hire Service Vehicle',
        '1507' => 'All Taxi Services',
        '1600' => 'Self Drive',
        '1601' => 'Hire Car',
        '1602' => 'Hire Van',
        '1603' => 'Hire Motorbike',
        '1604' => 'Hire Cycle',
        '1700' => 'Miscellaneous Service',
        '1701' => 'Cable Car',
        '1702' => 'Horse-drawn Carriage',
    ];

    const TRAM_TYPES = [
        '0', '900', '901', '902', '903', '904', '905', '906',
    ];

    CONST METRO_TYPES = [
        '1', '401', '402', '500', '600',
    ];
    CONST TRAIN_TYPES = [
        '2', '100', '101', '102', '103', '104', '105', '106', '107', '108', '109', '110', '111', '112', '113', '114',
        '115', '116', '117',
    ];
    const BUS_TYPES = [
        '3', '200', '201', '202', '203', '204', '205', '206', '207', '208', '209', '700', '701', '702', '703', '704',
        '705', '706', '707', '708', '709', '710', '711', '712', '713', '714', '715', '716', '800',
    ];

    const FERRY_TYPES = [
        '4', '1000', '1001', '1002', '1003', '1004', '1005', '1006', '1007', '1008', '1009', '1010', '1011', '1012',
        '1013', '1014', '1015', '1016', '1017', '1018', '1019', '1020', '1021',
    ];

    const CABLE_TYPES = [
        '5', '6', '7', '1302', '1701'
    ];

    public static function isBus(int $type): bool
    {
        return in_array($type, self::BUS_TYPES);
    }

    public static function isMetro(int $type): bool
    {
        return in_array($type, self::METRO_TYPES);
    }

    public static function isTrain(int $type): bool
    {
        return in_array($type, self::TRAIN_TYPES);
    }

    public static function isTram(int $type): bool
    {
        return in_array($type, self::TRAM_TYPES);
    }

    public static function isFerry(int $type): bool
    {
        return in_array($type, self::FERRY_TYPES);
    }
    public static function isCableCar(int $type): bool
    {
        return in_array($type, self::CABLE_TYPES);
    }

    /**
     * Map an extended GTFS route type to a basic route type. This can be useful to group for example bus services.
     * This works for tram, metro, train, bus and ferry services.
     *
     * @param int $type The type to convert.
     *
     * @return int The converted code. -1 if conversion failed.
     */
    public static function mapExtendedRouteTypeToBasicRouteType(int $type): int
    {

        if (self::isTram($type)) {
            return 0;
        }

        if (self::isMetro($type)) {
            return 1;
        }

        if (self::isTrain($type)) {
            return 2;
        }

        if (self::isBus($type)) {
            return 3;
        }
        if (self::isFerry($type)) {
            return 4;
        }

        if (self::isCableCar($type)) {
            return 5;
        }

        return -1;
    }

    public static function mapRouteTypeToText(int $type): string
    {
        if (self::isTram($type)) {
            return "Tram";
        }

        if (self::isMetro($type)) {
            return "Metro";
        }

        if (self::isTrain($type)) {
            return "Train";
        }

        if (self::isBus($type)) {
            return "Bus";
        }

        if (self::isFerry($type)) {
            return "Ferry";
        }

        if (self::isCableCar($type)) {
            return "Cable Car";
        }

        return "Route";
    }
}