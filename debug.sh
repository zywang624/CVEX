# cd ~/.cvex/bento_ubuntu-20.04/202407.23.0/1/
# vagrant snapshot restore mine/ubuntu

cd ~/.cvex/bento_ubuntu-22.04/202404.23.0/1/
vagrant snapshot restore mine2/ubuntu1

# cd ~/.cvex/bento_ubuntu-22.04/202404.23.0/2/
# vagrant snapshot restore mine2/ubuntu2

# vagrant ssh
vagrant ssh


# ip1: 192.168.56.3
# ip1: 192.168.56.4


# CVE-2017-8779
# sudo apt update
# sudo apt install golang
# mkdir ~/go
# echo "export GOPATH=$HOME/go" >> ~/.bashrc
# echo "export PATH=$PATH:$GOPATH/bin" >> ~/.bashrc
# source ~/.bashrc



# # Emix
# wget https://ftp.exim.org/pub/exim/exim4/old/exim-4.87.tar.gz
# tar -xzvf exim-4.87.tar.gz
# cd exim-4.87

# sudo apt update
# sudo apt install build-essential libssl-dev libpcre3-dev -y
# sudo apt-get install libdb-dev -y
# sudo apt-get install libx11-dev libxt-dev -y
# sudo apt-get install libxaw7-dev -y
# sudo apt-get install libgdbm-dev -y

# groupadd -g 31 exim &&
# useradd -d /dev/null -c "Exim Daemon" -g exim -s /bin/false -u 31 exim

# sed -e 's,^BIN_DIR.*$,BIN_DIRECTORY=/usr/sbin,' \
#     -e 's,^CONF.*$,CONFIGURE_FILE=/etc/exim.conf,' \
#     -e 's,^EXIM_USER.*$,EXIM_USER=exim,' \
#     -e 's,^EXIM_MONITOR,#EXIM_MONITOR,' src/EDITME > Local/Makefile &&
# printf "USE_GDBM = yes\nDBMLIB = -lgdbm\n" >> Local/Makefile &&
# make


# make install                                      &&
# install -v -m644 doc/exim.8 /usr/share/man/man8   &&
# install -v -d -m755 /usr/share/doc/exim-4.87    &&
# install -v -m644 doc/* /usr/share/doc/exim-4.87 &&
# ln -sfv exim /usr/sbin/sendmail                   &&
# install -v -d -m750 -o exim -g exim /var/spool/exim


# chmod -v a+wt /var/mail
# cat >> /etc/aliases << "EOF"
# postmaster: root
# MAILER-DAEMON: root
# EOF
# exim -v -bi &&
# /usr/sbin/exim -bd -q15m


# wget http://anduin.linuxfromscratch.org/BLFS/blfs-bootscripts/blfs-bootscripts-20160902.tar.xz
# tar -xvf blfs-bootscripts-20160902.tar.xz
# cd blfs-bootscripts-20160902
# make install-exim


sudo apt-get update
sudo apt-get install pkg-config -y
sudo apt-get install libssl-dev -y


wget https://ftp.exim.org/pub/exim/exim4/old/exim-4.89.tar.gz
tar -xzvf exim-4.89.tar.gz
cd exim-4.89

groupadd -g 31 exim &&
useradd -d /dev/null -c "Exim Daemon" -g exim -s /bin/false -u 31 exim


sed -e 's,^BIN_DIR.*$,BIN_DIRECTORY=/usr/sbin,'    \
    -e 's,^CONF.*$,CONFIGURE_FILE=/etc/exim.conf,' \
    -e 's,^EXIM_USER.*$,EXIM_USER=exim,'           \
    -e '/SUPPORT_TLS/s,^#,,'                       \
    -e '/USE_OPENSSL/s,^#,,'                       \
    -e 's,^EXIM_MONITOR,#EXIM_MONITOR,' src/EDITME > Local/Makefile &&
printf "USE_GDBM = yes\nDBMLIB = -lgdbm\n" >> Local/Makefile &&
make