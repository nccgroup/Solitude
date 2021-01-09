rule gpsData {

meta: 
gpsAlert = "Looks like the GPS coordinates *** "

strings: 


$mapBoxGPS = /"lat":(-?[\d\.]*),"lng":[-?\d\.]([-?\d\.]*)/  
$coStarGPS = /"lon":(-?[\d\.]*),"lat":[-?\d\.]([-?\d\.]*)/
$adsrvrGPS = /lat=(-?[\d\.]*)&lon=[-?\d\.]([-?\d\.]*)/
$test = /^[-+]?([1-8]?\d(\.\d+)?|90(\.0+)?),\s*[-+]?(180(\.0+)?|((1[0-7]\d)|([1-9]?\d))(\.\d+)?)$/
$test2 = /^(-?\d+(\.\d+)?),\s*(-?\d+(\.\d+)?)$/
$test3 = /"longitude":(-?[\d\.]*),"latitude":[-?\d\.]([-?\d\.]*)/
$lat = /(\"lat\"|\"latitude\"):(-?[\d\.]*)/

condition: $coStarGPS or $mapBoxGPS or $adsrvrGPS or $test or $test2 or $test3 or $lat

}

rule wordSearchGPS {


meta:
wordsearchGPSAlert = "The following strings appear to be GPS terms very well could be a false positive *** "

strings:
$Latitude = "Latitude" nocase
$Longitude = "Longitude" nocase
condition:
    $Latitude or $Longitude

}

