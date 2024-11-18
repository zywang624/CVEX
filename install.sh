wget https://repository.timesys.com/buildsources/p/polkit/polkit-0.104/polkit-0.104.tar.gz

tar -xvzf polkit-0.104.tar.gz

cd polkit-0.104

sudo apt update
sudo apt install build-essential autoconf automake libtool pkg-config libglib2.0-dev libpolkit-gobject-1-dev
sudo apt install libexpat1-dev
sudo apt install libpam0g-dev
sudo apt install intltool

./configure
make
sudo make install