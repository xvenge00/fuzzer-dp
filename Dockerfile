FROM archlinux/archlinux

RUN sed -i 's/^Include.*$/SigLevel = PackageRequired\nServer=https:\/\/archive.archlinux.org\/repos\/2021\/04\/30\/$repo\/os\/$arch/' /etc/pacman.conf && \
    echo 'Server=https://archive.archlinux.org/repos/2021/04/30/$repo/os/$arch' > /etc/pacman.d/mirrorlist && \
    pacman -Syyyu && \
    pacman -S cmake gcc make libpcap spdlog yaml-cpp boost --noconfirm
