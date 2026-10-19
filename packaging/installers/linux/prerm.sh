#!/bin/sh
# Pre-removal script of the smcp .deb (prerm) and .rpm (%preun) packages,
# the only maintainer script they have (SRS FR-20.21, FR-20.22; audited by
# TestLinuxPackageScripts in cmd/smcpctl/platformpkg_test.go).
#
# On removal, and only then, it asks the packaged smcpctl to stop and
# remove the system-wide smcpd service that `smcpctl install --profile
# enforced` created. It never touches configuration, state, the evidence
# journal, keys or backups, and it never fails the removal.
#
# dpkg passes "remove" or "purge" on removal and "upgrade", "deconfigure"
# or "failed-upgrade" otherwise; rpm passes the number of versions left
# after the transaction: 0 on erase, 1 or more on upgrade.
case "$1" in
remove | purge | 0) ;;
*) exit 0 ;;
esac
if [ -x /usr/bin/smcpctl ]; then
	/usr/bin/smcpctl uninstall --package-removal ||
		echo "smcp: could not stop the system smcpd service; stop it with: systemctl disable --now smcpd.service" >&2
fi
exit 0
