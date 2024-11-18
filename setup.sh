sudo apt update
sudo apt install zsh -y
sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
vim ~/.zshrc

git config --global user.email 891922758@qq.com
git config --global user.name vincent

sudo apt install python3.10-venv -y

python3 -m venv venv
source venv/bin/activate

sudo apt update
sudo apt install git-lfs -y
git lfs pull
pip install -e .

wget https://releases.hashicorp.com/vagrant/2.4.1/vagrant-2.4.1-1.x86_64.rpm
sudo apt install alien -y
sudo alien -i vagrant-2.4.1-1.x86_64.rpm

sudo apt-add-repository ppa:ansible/ansible
sudo apt update
sudo apt install ansible

wget https://download.virtualbox.org/virtualbox/7.0.20/virtualbox-7.0_7.0.20-163906~Ubuntu~jammy_amd64.deb
sudo dpkg -i virtualbox-7.0_7.0.20-163906~Ubuntu~jammy_amd64.deb
sudo apt --fix-broken install -y
sudo dpkg -i virtualbox-7.0_7.0.20-163906~Ubuntu~jammy_amd64.deb
wget https://download.virtualbox.org/virtualbox/7.0.20/Oracle_VM_VirtualBox_Extension_Pack-7.0.20.vbox-extpack
sudo vboxmanage extpack install Oracle_VM_VirtualBox_Extension_Pack-7.0.20.vbox-extpack

