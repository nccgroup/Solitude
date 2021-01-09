




rule adTracking {

meta:  adTrackingAlert = "Ad tracking is limited neat! (from yara) Your null Ad ID *** "

strings: $nulAdID =  "00000000-0000-0000-0000-000000000000" fullword nocase
                     

condition: $nulAdID


}

rule carrier {
 
 meta: carrierAlert = "Your mobile provider ***  "
 
 strings:
 $ATT = "AT&T" nocase fullword
 $Sprint = "sprint" nocase fullword
 $TMobile = "tmobile" nocase fullword
 $tmobile = "t-mobile" nocase fullword
 $Verizon = "verizon" nocase fullword

condition: $ATT or $Sprint or $TMobile or $tmobile or $Verizon

}

rule timeZone {

meta: timeZoneAlert = "Your Time Zone *** "

strings:

$PST = "America\\/Los_Angeles" nocase fullword
$PST2 = "America\\\\/Los_Angeles" nocase 

condition: $PST or $PST2


}


rule ipAddress {

meta: ipAddress = "This appears to be an IP address *** "

strings:

$ipRegex = /192\.168\.[0-9]{1,3}\.[0-9]{1,3}|(172\.([1][6-9]|[2][0-9]|[3][0-1])\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5]))|(10\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\.([0-2][0-5][0-5]|[0-9][0-9]|[0-9]))/




condition: $ipRegex


}

rule macAddress {

meta: macAddress = "This appears to be a mac address *** "

strings:

$macAddress = /(([0-9A-F]{2}[:-]){5}([0-9A-F]{2}))/

condition: $macAddress


}




