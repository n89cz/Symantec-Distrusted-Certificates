#!/bin/bash
#
# Find distrusted Symantec certificates
#

# TODO:

. /shared/linux/log.sh

BASE=/shared/temp/md162/symantec_certificates
BLACKLIST="symantec_blacklist.txt"
HOSTNAME="$(hostname)"
CRT_D=/data/web/certs
TMP_LIST="crt.list"
TMP_DIR=$BASE/tmp/$HOSTNAME
WANTED_LIST=$TMP_DIR/wanted.list
LOGPRF=$BASE/log/$HOSTNAME/log
APP_PID=$$
MATCH_COUNT=0

loginit

log "Script started with PID $APP_PID"

# check parameters count
if [ "$#" -ne 0 ] ; then
    log "Wrong script usage"
    log "Script accept no parameters"
    log "Exiting, bye"
    exit 1
fi

mkdir -p $TMP_DIR

symantec_not_found() {
log "No Symantec certificates found"
}

symantec_found() {
log "We have found $MATCH_COUNT Symantec certificate(s)"
}

send_email() {
log "Sending email with Symantec certificates list"
cat $WANTED_LIST | mail -s "Symantec certificate(s) found" -r "$HOSTNAME@wedos.net" list-server@wedos.com
}

clean_temp_files() {
log "Removing temporary files"
rm -r $TMP_DIR || log "Unable to remove $TMP_DIR folder"
}

# here we find all .crt in CRT_D on current server and store them in TMP_LIST
log "Looking for certificates"
find $CRT_D -name "*.crt" >> $TMP_DIR/$TMP_LIST

# read all distrusted ($BLACKLIST) certificates line by line and compare them with our certificates OUR_CRT
while read DISTRUSTED
do
    while read OUR_CRT
    do
	# get hash of public certificate
	SYMANTEC_HASH=$(openssl x509 -noout -pubkey -in $OUR_CRT | openssl asn1parse -inform pem -out $TMP_DIR/pubkey.out -noout; digest=`cat $TMP_DIR/pubkey.out | openssl dgst -sha256 -c | awk -F " " '{print $2}' | sed s/:/,0x/g `; echo "0x${digest} ${f##*/}";)
	SYMANTEC_NO_WHITESPACE="$(echo "${SYMANTEC_HASH}" | tr -d '[:space:]')"
	
	# lets compare blacklist with our certificates hashes
	if [ "$DISTRUSTED" = "$SYMANTEC_NO_WHITESPACE" ] ; then
	
	# if match found add webhosting ID to wanted list and increase number of found certificates
	VIRTUAL="$(echo "${OUR_CRT}" | cut -d '/' -f 5)"
	echo $VIRTUAL >> $WANTED_LIST
	MATCH_COUNT=$((MATCH_COUNT+1))
	fi
    done < "$TMP_DIR/$TMP_LIST"
done < "$BLACKLIST"

if [ $MATCH_COUNT -eq 0 ] ; then
    symantec_not_found
    clean_temp_files
    log "Exiting, bye"
    exit 0
elif [ $MATCH_COUNT -gt 0 ] ; then
    symantec_found
    send_email
    clean_temp_files
    log "Exiting, bye"
    exit 0
else
    log "Error occurred :-("
    log "MATCH_COUNT VALUE: $MATCH_COUNT"
    exit 1
fi
