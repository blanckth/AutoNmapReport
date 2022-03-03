#!/usr/bin/env bash
# Authur : Salar Muhammadi
#
declare -r XMLfile="scan/sL.xml";
declare -r CSVfile="summery/sL.csv";
declare -r SCSV="summery/servers.csv";
declare -r CCSV="summery/clients.csv";
#
#dependencies
depend () {
sudo apt-get update && sudo apt-get install -y xml2 xmlstarlet nmap;
#
}
declare -r netID='172.23.10.0/24';
[[ -d scan ]] || mkdir -v scan;
[[ -d summery ]] || mkdir -v summery;
# Full Scan NetID for IP and Names
netIpScan () {
	nmap -v -d -sL -oX "$XMLfile" "$netID";
	xml2 < "$XMLfile" | 2csv host @addr @name @type > "$CSVfile";
}
ipFiltering () {
	OLDIFS=$IFS;
	local -i countS=1;
	local -i countC=1;
	#
	while IFS=, read -r ip name type; do
		if [[ -z "${name}" ]]; then
			echo "$countC,$ip" >> "$CCSV";
			countC+=1;
		else
			echo "$countS,$ip,$name,$type" >> "$SCSV";
			countS+=1;
		fi;
	done < $CSVfile;
	IFS=$OLDIFS;
}
[[ -d summery/server ]] || mkdir -v summery/server;
# PORT SCAN : ARGs [IP] [Dest]
portScan () {
	nmap -v -d -A -r "$1" -oX "$2/$1.xml";
}

declare -r serv="summery/server";
serverPS () {
OLDIFS=$IFS;
while IFS=, read -r num ip name type; do
	echo "Scanning ports of : $name on $ip ...";
	portScan "$ip" "$serv";
done < $SCSV;
IFS=$OLDIFS;
}
portSum () {
	[[ -d "$1/sum" ]] || mkdir -v "$1/sum";
	local sumCSV="$1/sum/ports.csv";
	echo "Port Summerize" > "$sumCSV";
	local -a sip=$( ls -v "$1" );
	local -i ipc=1;
	for ipx in $sip; do
		if [[ ! -d "$1/$ipx" ]]; then
		ipn="${ipx%.*}"
		local ipdir="$1/$ipn";
		[[ -d "$ipdir" ]] || mkdir -v "$ipdir";
			#xml2 < "$1/$ipx" | 2csv address @addr > "$1/$ipx.addr.csv";
			xmlstarlet select -t -v 'nmaprun/host/address/@addr' --nl "$1/$ipx" > "$ipdir/$ipn.addr.tmp";
			xmlstarlet select -t -v 'nmaprun/host/ports/port/@portid' --nl "$1/$ipx" > "$ipdir/$ipn.portid.tmp";
			xmlstarlet select -t -v 'nmaprun/host/ports/port/@protocol' --nl "$1/$ipx" > "$ipdir/$ipn.protocol.tmp";
			xmlstarlet select -t -v 'nmaprun/host/ports/port/state/@state' --nl "$1/$ipx" > "$ipdir/$ipn.state.tmp";
			xmlstarlet select -t -v 'nmaprun/host/ports/port/service/@name' --nl "$1/$ipx" > "$ipdir/$ipn.service.tmp";
			local -a ipnaddr=();
			while read -r line; do
				ipnaddr+=($line);
			done < "$ipdir/$ipn.addr.tmp";
			echo 0,"${ipnaddr[0]}","${ipnaddr[1]}" > "$ipdir/$ipn.csv" ;
			###
			local -a ipnport=();
			while read -r line; do
				ipnport+=($line);
			done < "$ipdir/$ipn.portid.tmp";
			local -a ipnprot=();
			while read -r line; do
				ipnprot+=($line);
			done < "$ipdir/$ipn.protocol.tmp";
			local -a ipnstate=();
			while read -r line; do
				ipnstate+=($line);
			done <  "$ipdir/$ipn.state.tmp";
			local -a ipnservice=();
			while read -r line; do
				ipnservice+=($line);
			done < "$ipdir/$ipn.service.tmp";
			local -i pcount=0;
			for port in ${ipnport[@]}; do
				echo "$(( $pcount + 1 )),${ipnprot[$pcount]},$port,${ipnstate[$pcount]},${ipnservice[$pcount]}" >> "$ipdir/$ipn.csv";
				pcount+=1;
			done;
			local -a ipnsuma=();
			OLDIFS=$IFS;
			while IFS=, read -r num one two three four; do
				if [[ $num -eq 0 ]]; then
					ipnsuma+=("$one");
					ipnsuma+=("$two");
				else
					ipnsuma+=("$one/$two/$three/$four")
				fi;
			done < "$ipdir/$ipn.csv";
			IFS=$OLDIFS;
			local csvsum="$ipc,";
			for (( c=0; c<${#ipnsuma[@]}; c++ )); do
				csvsum+="${ipnsuma[$c]},"
			done;
			echo "$csvsum" >> "$sumCSV";
			ipc+=1;
		fi;
	done;
}
serverCSVX () {
	portSum "$serv"
}
[[ -d summery/client ]] || mkdir -v summery/client;
declare -r clie="summery/client";
clientPS () {
OLDIFS=$IFS;
while IFS=, read -r num ip; do
	echo "Scanning ports of : $ip";
	portScan "$ip" "$clie";
done < $CCSV;
IFS=$OLDIFS;
}
clientCSVX () {
	portSum "$clie";
}
MAIN () {
#depend;
#netIpScan;
#ipFiltering;
#serverPS;
#clientPS;
#serverCSVX;
clientCSVX;
}
MAIN;
