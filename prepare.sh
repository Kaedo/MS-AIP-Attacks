#!/usr/bin/env bash
function normalize_cert_and_license {
	CERTs=`find input/ -iname "*.drm" | grep -v keyfile`
	for FILE in $CERTs; do
		echo ""
		echo "Normalize the format of file: $FILE"
		in="$FILE"
		out=''
		if [[ $FILE == *"Machine"* ]]; then
			out=`echo $FILE| cut -d'/' -f2- | cut -d'.' -f1`
		else
			out=`echo $FILE| cut -d'/' -f2- | cut -d'-' -f1`
		fi
		out="processed/$out.drm.xrml"
		cat $in | tr -dc '[:print:]' | sed 's/></>\n</g' > $out
	done 

}

function normalize_sk_and_mk {
	OTHERs=`find input/ -iname "*.hex"`
	for FILE in $OTHERs; do
		echo ""
		echo "Normalize the format of file: $FILE"
		in="$FILE"
		out=`echo $FILE| cut -d'/' -f2-`
		out="processed/$out"
		cat $in | tr -dc '[:print:]' > $out
	done 
}

function extract_spc_modulus {
	echo "Try to extract RSA modulus from 2048 bit normalized SPC"

	SPC2048=`find processed/ -iname "CERT-Machine-2048.drm.xrml"`
	for FILE in $SPC2048; do
		echo ""
		echo "Found $FILE"
		pk=`cat $FILE | grep "<NAME>Machine</NAME>" -A8 | grep '<VALUE encoding="base64" size="2048">' | cut -d'>' -f2| cut -d'<' -f1`
		hex=`echo "$pk" | base64 -d | xxd -p |  tr -d '\n'`
		echo -e "File $FILE has 2048 RSA modulus of: $hex"
		echo -e "Write modulus to $FILE.modulus"
		echo "$hex" > "$FILE.modulus"
	done

}	

function extract_pl_authorization_data {
	echo "\nTry to extract Authorization data from Publishing License"

	PL=`find processed/ -iname "PL.drm.xrml"`
	for FILE in $PL; do
		echo ""
		echo "Found $FILE"
		erd=`cat $FILE | grep "Encrypted-Rights-Data" | cut -d'>' -f2- | cut -d'<' -f1`
		hex=`echo "$erd" | base64 -d | xxd -p |  tr -d '\n'`
		echo -e "File $FILE has Encrypted-Rights-Data of: $hex"
		echo -e "Write ERD to $FILE.erd"
		echo "$hex" > "$FILE.erd"
	done

}	



function extract_enablingbits_from_cert {
	echo "Try to extract ENABLING BITS element from Certificates"
	CERTs=`find processed/ -iname "*drm.xrml" | grep -v CERT-Machine`
	for FILE in $CERTs; do
		echo ""
		echo "Found $FILE"
		enabits=`cat $FILE | grep "</ENABLINGBITS>" -B2 | cut -d'>' -f2| cut -d'<' -f1`
		hex=`echo "$enabits" | base64 -d | xxd -p |  tr -d '\n'`
		echo -e "File $FILE has ENABLINGBITS element of: $hex"
		echo -e "Write ENABLINGBITS to $FILE.enablingbits"
		echo "$hex" > "$FILE.enablingbits"
	done

}

normalize_cert_and_license
normalize_sk_and_mk
extract_spc_modulus
extract_enablingbits_from_cert
extract_pl_authorization_data
