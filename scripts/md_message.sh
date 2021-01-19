#!/bin/sh
#
# Sample script to configure for MDMessageCmd.
# 
# Edit the USER you want to notify. Comment the "msg=" lines where 
# you do not want to receive notifications for.
#

action="$1"
domain="$2"

USER="webmaster@$domain"

case "$action" in
    "renewing")
        subject="renewing $domain certificate"
        msg="Your Apache starts renewing the certificate for '$domain'."
        ;;
    "renewed")
        subject="renewed $domain certificate"
        msg="Your Apache renewed the certificate for '$domain'. It will become active after a server reload."
        ;;
    "installed")
        subject="installed $domain certificate"
        msg="Your Apache installed the certificate for '$domain'. It is now active."
        ;;
    "expiring")
        subject="expiring $domain certificate"
        msg="Your Apache reports that the certificate for '$domain' will soon expire."
        ;;
    "errored")
        subject="error renewing $domain certificate"
        msg="There was an error renewing the certificate for '$domain'. Apache will continue trying. Please check the md-status resources or the server log for more information should this repeat."
        ;;
    "ocsp-renewed")
        subject="refreshed OCSP stapling for $domain"
        msg="The OCSP stapling information for '$domain' was successfully refreshed."
        ;;
    "ocsp-errored")
        subject="error refreshing OCSP stapling for $domain"
        msg="The was an error refreshing the OCSP stapling information for '$domain'. Apache will continue trying. Please check the md-status resources or the server log for more information should this repeat."
        ;;
    *)
        subject="unknown action in MD message"
        msg="Your Apache reported action '$action' for domain '$domain'."
esac

if test "x$msg" = "x"; then exit 0; fi

mail -s "$subject" "$USER" <<EOF
$msg
EOF
