#!/bin/sh

echo "This is the wine64-bin helper package, which does not provide wine itself,"
echo "but instead exists solely to provide the following information about"
echo "enabling multiarch on your system in order to be able to install and run"
echo "the 32-bit wine packages."
echo ""
echo "The following commands should be issued as root or via sudo in order to"
echo "enable multiarch (the last command installs 32-bit wine):"
echo ""
echo "  # dpkg --add-architecture i386"
echo "  # sed -i 's/deb\ /deb\ [arch=amd64,i386]\ /g' /etc/apt/sources.list"
echo "  # apt-get update"
echo "  # apt-get install wine-bin:i386"
echo ""
echo "Be very careful as spaces matter above.  For kfreebsd systems, replace i386"
echo "and amd64 with kfreebsd-i386 and kfreebsd-amd64.  Note that this package"
echo "(wine64-bin) will be removed in the process.  For more information on the"
echo "multiarch conversion, see:"
echo "http://wiki.debian.org/Multiarch/HOWTO"
