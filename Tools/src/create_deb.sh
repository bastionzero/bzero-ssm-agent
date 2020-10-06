#!/usr/bin/env bash
set -e

ARCH=$1

echo "****************************************"
echo "Creating deb file for Ubuntu Linux $ARCH"
echo "****************************************"

rm -rf ${GO_SPACE}/bin/debian_${ARCH}/debian

if [[ "$ARCH" == "arm" ]]; then
  DEB_ARCH="armhf"
elif [[ "$ARCH" == "386" ]]; then
  DEB_ARCH="i386"
else
  DEB_ARCH=$ARCH
fi

echo "Creating debian folders debian_$ARCH"

mkdir -p ${GO_SPACE}/bin/debian_${ARCH}/debian/usr/bin/
mkdir -p ${GO_SPACE}/bin/debian_${ARCH}/debian/etc/init/
mkdir -p ${GO_SPACE}/bin/debian_${ARCH}/debian/etc/bzero/ssm/
mkdir -p ${GO_SPACE}/bin/debian_${ARCH}/debian/usr/share/doc/bzero-ssm-agent/
mkdir -p ${GO_SPACE}/bin/debian_${ARCH}/debian/usr/share/lintian/overrides/
mkdir -p ${GO_SPACE}/bin/debian_${ARCH}/debian/var/lib/bzero/ssm/
mkdir -p ${GO_SPACE}/bin/debian_${ARCH}/debian/lib/systemd/system/

echo "Copying application files debian_$ARCH"

cp ${GO_SPACE}/bin/linux_${ARCH}/amazon-ssm-agent ${GO_SPACE}/bin/debian_${ARCH}/debian/usr/bin/bzero-ssm-agent
cp ${GO_SPACE}/bin/linux_${ARCH}/ssm-agent-worker ${GO_SPACE}/bin/debian_${ARCH}/debian/usr/bin/bzero-ssm-agent-worker
cp ${GO_SPACE}/bin/linux_${ARCH}/ssm-cli ${GO_SPACE}/bin/debian_${ARCH}/debian/usr/bin/bzero-ssm-cli
cp ${GO_SPACE}/bin/linux_${ARCH}/ssm-document-worker ${GO_SPACE}/bin/debian_${ARCH}/debian/usr/bin/bzero-ssm-document-worker
cp ${GO_SPACE}/bin/linux_${ARCH}/ssm-session-worker ${GO_SPACE}/bin/debian_${ARCH}/debian/usr/bin/bzero-ssm-session-worker
cp ${GO_SPACE}/bin/linux_${ARCH}/ssm-session-logger ${GO_SPACE}/bin/debian_${ARCH}/debian/usr/bin/bzero-ssm-session-logger
cp ${GO_SPACE}/seelog_unix.xml ${GO_SPACE}/bin/debian_${ARCH}/debian/etc/bzero/ssm/seelog.xml
cp ${GO_SPACE}/amazon-ssm-agent.json.template ${GO_SPACE}/bin/debian_${ARCH}/debian/etc/bzero/ssm/
cp ${GO_SPACE}/packaging/ubuntu/amazon-ssm-agent.conf ${GO_SPACE}/bin/debian_${ARCH}/debian/etc/init/bzero-ssm-agent.conf
cp ${GO_SPACE}/packaging/ubuntu/amazon-ssm-agent.service ${GO_SPACE}/bin/debian_${ARCH}/debian/lib/systemd/system/bzero-ssm-agent.service

echo "Copying debian package config files debian_$ARCH"

cp ${GO_SPACE}/RELEASENOTES.md ${GO_SPACE}/bin/debian_${ARCH}/debian/etc/bzero/ssm/RELEASENOTES.md
cp ${GO_SPACE}/README.md ${GO_SPACE}/bin/debian_${ARCH}/debian/etc/bzero/ssm/README.md
cp ${GO_SPACE}/NOTICE.md ${GO_SPACE}/bin/debian_${ARCH}/debian/etc/bzero/ssm/
cp ${GO_SPACE}/Tools/src/LICENSE ${GO_SPACE}/bin/debian_${ARCH}/debian/usr/share/doc/bzero-ssm-agent/copyright
cp ${GO_SPACE}/packaging/ubuntu/conffiles ${GO_SPACE}/bin/debian_${ARCH}/debian/
cp ${GO_SPACE}/packaging/ubuntu/docs ${GO_SPACE}/bin/debian_${ARCH}/debian/
cp ${GO_SPACE}/packaging/ubuntu/preinst ${GO_SPACE}/bin/debian_${ARCH}/debian/
cp ${GO_SPACE}/packaging/ubuntu/postinst ${GO_SPACE}/bin/debian_${ARCH}/debian/
cp ${GO_SPACE}/packaging/ubuntu/prerm ${GO_SPACE}/bin/debian_${ARCH}/debian/
cp ${GO_SPACE}/packaging/ubuntu/lintian-overrides ${GO_SPACE}/bin/debian_${ARCH}/debian/usr/share/lintian/overrides/bzero-ssm-agent

echo "Constructing the control file debian_$ARCH"

echo 'Package: bzero-ssm-agent' > ${GO_SPACE}/bin/debian_${ARCH}/debian/control
echo "Architecture: ${DEB_ARCH}" >> ${GO_SPACE}/bin/debian_${ARCH}/debian/control
echo -n 'Version: ' >> ${GO_SPACE}/bin/debian_${ARCH}/debian/control
cat ${GO_SPACE}/VERSION | tr -d "\n" >> ${GO_SPACE}/bin/debian_${ARCH}/debian/control
echo '-1' >> ${GO_SPACE}/bin/debian_${ARCH}/debian/control
cat ${GO_SPACE}/packaging/ubuntu/control >> ${GO_SPACE}/bin/debian_${ARCH}/debian/control

echo "Constructing the changelog file debian_$ARCH"

echo -n 'bzero-ssm-agent (' > ${GO_SPACE}/bin/debian_${ARCH}/debian/usr/share/doc/bzero-ssm-agent/changelog
cat VERSION | tr -d "\n"  >> ${GO_SPACE}/bin/debian_${ARCH}/debian/usr/share/doc/bzero-ssm-agent/changelog
echo '-1) unstable; urgency=low' >> ${GO_SPACE}/bin/debian_${ARCH}/debian/usr/share/doc/bzero-ssm-agent/changelog
cat ${GO_SPACE}/packaging/ubuntu/changelog >> ${GO_SPACE}/bin/debian_${ARCH}/debian/usr/share/doc/bzero-ssm-agent/changelog

cp ${GO_SPACE}/packaging/ubuntu/changelog.Debian ${GO_SPACE}/bin/debian_${ARCH}/debian/usr/share/doc/bzero-ssm-agent/
cp ${GO_SPACE}/packaging/ubuntu/debian-binary ${GO_SPACE}/bin/debian_${ARCH}/debian/

echo "Setting permissions as required by debian_$ARCH"

cd ${GO_SPACE}/bin/debian_${ARCH}/; find ./debian -type d | xargs chmod 755; cd ~-

echo "Compressing changelog for debian_$ARCH"

cd ${GO_SPACE}/bin/debian_${ARCH}/debian/usr/share/doc/bzero-ssm-agent/; export GZIP=-9; tar cvzf changelog.gz changelog --owner=0 --group=0 ; cd ~-
cd ${GO_SPACE}/bin/debian_${ARCH}/debian/usr/share/doc/bzero-ssm-agent/; export GZIP=-9; tar cvzf changelog.Debian.gz changelog.Debian --owner=0 --group=0; cd ~-

rm ${GO_SPACE}/bin/debian_${ARCH}/debian/usr/share/doc/bzero-ssm-agent/changelog
rm ${GO_SPACE}/bin/debian_${ARCH}/debian/usr/share/doc/bzero-ssm-agent/changelog.Debian

echo "Creating tar for debian_$ARCH"
# the below permissioning is required by debian
cd ${GO_SPACE}/bin/debian_${ARCH}/debian/; tar czf data.tar.gz usr etc lib --owner=0 --group=0 ; cd ~-
cd ${GO_SPACE}/bin/debian_${ARCH}/debian/; tar czf control.tar.gz control conffiles docs preinst postinst prerm --owner=0 --group=0 ; cd ~-

echo "Constructing the deb package debian_$ARCH"
ar r ${GO_SPACE}/bin/debian_${ARCH}/bzero-ssm-agent.deb ${GO_SPACE}/bin/debian_${ARCH}/debian/debian-binary
ar r ${GO_SPACE}/bin/debian_${ARCH}/bzero-ssm-agent.deb ${GO_SPACE}/bin/debian_${ARCH}/debian/control.tar.gz
ar r ${GO_SPACE}/bin/debian_${ARCH}/bzero-ssm-agent.deb ${GO_SPACE}/bin/debian_${ARCH}/debian/data.tar.gz

