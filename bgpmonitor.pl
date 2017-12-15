#!/usr/bin/perl
#
# Router bgp (Border Gateway Protocol v4 ) monitor
# look at each router and get the status of all is BGP neigbor
#
# Version 1.1( June, 2006)
# 
# Copyright 2002, Marc Hauswirth, Safe Host SA <marc@safehostnet.com>
# Copyright 2005, Val Glinskiy, <vglinskiy@gmail.com>
# Some inspiration is taken from Marc Hauswirth's script http://www.kernel.org/pub/software/admin/mon/contrib/monitors/bgp/bgp.monitor
#
# License: GNU GPL v2, see http://www.gnu.org/copyleft/gpl.html
#
# This script was tested with Cisco 7204 and 6503
#
#
# This script needs Net::SNMP  module
#
# Usage: bgpmonitor.pl <router1> <router2> ... <routerN>
# Eigther name or IP address can be used

use Net::SNMP qw(:snmp);
use strict;

## --
# Change "public" to your SNMP community :
my $community = "public";

## --


# OID's to the SNMP elements that I want to show...
# From Cisco's MIB and RFC's
# http://tools.cisco.com/Support/SNMP/do/BrowseMIB.do?local=en&step=2&mibName=BGP4-MIB

my %oids = ( 
        "SysUptime"                     =>      "1.3.6.1.2.1.1.3.0",
        "bgpVersion"                    =>      "1.3.6.1.2.1.15.1.0",
        "bgpLocalAs"                    =>      "1.3.6.1.2.1.15.2.0",

#       "bgpPeerTable"                  =>      "1.3.6.1.2.1.15.3",
        "bgpPeerEntry"                  =>      "1.3.6.1.2.1.15.3.1",
        "bgpPeerIdentifier"             =>      "1.3.6.1.2.1.15.3.1.1",
        "bgpPeerState"                  =>      "1.3.6.1.2.1.15.3.1.2",
        "bgpPeerAdminStatus"            =>      "1.3.6.1.2.1.15.3.1.3",
        "bgpPeerNegotiatedVersion"      =>      "1.3.6.1.2.1.15.3.1.4",
        "bgpPeerLocalAddr"              =>      "1.3.6.1.2.1.15.3.1.5",
        "bgpPeerLocalPort"              =>      "1.3.6.1.2.1.15.3.1.6",
        "bgpPeerRemoteAddr"             =>      "1.3.6.1.2.1.15.3.1.7",
        "bgpPeerRemotePort"             =>      "1.3.6.1.2.1.15.3.1.8",
        "bgpPeerRemoteAs"               =>      "1.3.6.1.2.1.15.3.1.9",
        "bgpPeerInUpdates"              =>      "1.3.6.1.2.1.15.3.1.10",
        "bgpPeerOutUpdates"             =>      "1.3.6.1.2.1.15.3.1.11",
        "bgpPeerInTotalMessages"        =>      "1.3.6.1.2.1.15.3.1.12",
        "bgpPeerOutTotalMessages"       =>      "1.3.6.1.2.1.15.3.1.13",
        "bgpPeerLastError"              =>      "1.3.6.1.2.1.15.3.1.14",
        "bgpPeerFsmEstablishedTransitions" =>   "1.3.6.1.2.1.15.3.1.15",
        "bgpPeerFsmEstablishedTime"     =>      "1.3.6.1.2.1.15.3.1.16",
        "bgpPeerConnectRetryInterval"   =>      "1.3.6.1.2.1.15.3.1.17",
        "bgpPeerHoldTime"               =>      "1.3.6.1.2.1.15.3.1.18",
        "bgpPeerKeepAlive"              =>      "1.3.6.1.2.1.15.3.1.19",
        "bgpPeerHoldTimeConfigured"     =>      "1.3.6.1.2.1.15.3.1.20",
        "bgpPeerKeepAliveConfigured"    =>      "1.3.6.1.2.1.15.3.1.21",
        "bgpPeerMinASOriginationInterval" =>    "1.3.6.1.2.1.15.3.1.22",
        "bgpPeerMinRouteAdvertisementInterval" => "1.3.6.1.2.1.15.3.1.23",
        "bgpPeerInUpdateElapsedTime"    =>      "1.3.6.1.2.1.15.3.1.24",
        "bgpIdentifier"                 =>      "1.3.6.1.2.1.15.4",
        "bgpRcvdPathAttrTable"          =>      "1.3.6.1.2.1.15.5",
        "bgp4PathAttrTable"             =>      "1.3.6.1.2.1.15.6",
        "bgpPathAttrEntry"              =>      "1.3.6.1.2.1.15.5.1",
        "bgpPathAttrPeer"               =>      "1.3.6.1.2.1.15.5.1.1",
        "bgpPathAttrDestNetwork"        =>      "1.3.6.1.2.1.15.5.1.2",
        "bgpPathAttrOrigin"             =>      "1.3.6.1.2.1.15.5.1.3",
        "bgpPathAttrASPath"             =>      "1.3.6.1.2.1.15.5.1.4",
        "bgpPathAttrNextHop"            =>      "1.3.6.1.2.1.15.5.1.5",
        "bgpPathAttrInterASMetric"      =>      "1.3.6.1.2.1.15.5.1.6",
        "bgp4PathAttrEntry"             =>      "1.3.6.1.2.1.15.6.1",
        "bgp4PathAttrPeer"              =>      "1.3.6.1.2.1.15.6.1.1",
        "bgp4PathAttrIpAddrPrefixLen"   =>      "1.3.6.1.2.1.15.6.1.2",
        "bgp4PathAttrIpAddrPrefix"      =>      "1.3.6.1.2.1.15.6.1.3",
        "bgp4PathAttrOrigin"            =>      "1.3.6.1.2.1.15.6.1.4",
        "bgp4PathAttrASPathSegment"     =>      "1.3.6.1.2.1.15.6.1.5",
        "bgp4PathAttrNextHop"           =>      "1.3.6.1.2.1.15.6.1.6",
        "bgp4PathAttrMultiExitDisc"     =>      "1.3.6.1.2.1.15.6.1.7",
        "bgp4PathAttrLocalPref"         =>      "1.3.6.1.2.1.15.6.1.8",
        "bgp4PathAttrAtomicAggregate"   =>      "1.3.6.1.2.1.15.6.1.9",
        "bgp4PathAttrAggregatorAS"      =>      "1.3.6.1.2.1.15.6.1.10",
        "bgp4PathAttrAggregatorAddr"    =>      "1.3.6.1.2.1.15.6.1.11",
        "bgp4PathAttrCalcLocalPref"     =>      "1.3.6.1.2.1.15.6.1.12",
        "bgp4PathAttrBest"              =>      "1.3.6.1.2.1.15.6.1.13",
        "bgp4PathAttrUnknown"           =>      "1.3.6.1.2.1.15.6.1.14",
        );


my %BgpPeerState = (
        1 => "idle",
        2 => "connect",
        3 => "active",
        4 => "opensnet",
        5 => "openconfirm",
        6 => "established"
        );


my %state;

foreach my $router (@ARGV) {
        # Get some infos about this router
        my ($sess, $error) = Net::SNMP->session ( -hostname => $router, -community => $community, -versi
on => 2 )|| die "Can not connect ";
        my $result = $sess->get_request(-varbindlist => [$oids{bgpLocalAs}]);

        printf("\n=============================\nRouter: %s  AS %s \n", $router, $result->{$oids{bgpLoca
lAs}} ) ;

# if you get "Message size exceeded buffer maxMsgSize" error, try reducing -maxrepetitions
 
        my $results = $sess->get_bulk_request(-varbindlist => [$oids{bgpPeerRemoteAddr}], -maxrepetition
s =>20 );
        if (!defined($results)){
         print "$oids{bgpPeerRemoteAddr} No results\n";
         printf("ERROR: %s\n",$sess->error);
         exit 1;
        }

        my $key;
       my %vals=%{$results};
        foreach $key (keys %vals) {
         if(oid_base_match($oids{bgpPeerRemoteAddr}, $key)) {
          my $PeerState;
          my $oidPeerStatus=$oids{bgpPeerState}.".".$vals{$key};
          $PeerState = $sess->get_request(-varbindlist => [$oidPeerStatus]);

        if (!defined($PeerState)){
         print "$oidPeerStatus  No results\n";
         printf("ERROR: %s\n",$sess->error);
         exit 1;
        }
           print ( "Neighbor:\t", $vals{$key},"\t Status:\t",$BgpPeerState{$PeerState->{$oidPeerStatus} 
},"\n");
         }
        }
$sess->close;

}

