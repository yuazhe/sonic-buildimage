set -ex
cd /sonic/src/sonic-cpp-coverage

# Install gcovr
git clone https://github.com/gcovr/gcovr.git
cd gcovr/
git checkout 5.2
sudo pip3 install setuptools
sudo python3 setup.py install
cd ..
sudo rm -rf gcovr

# Install redis
sudo apt-get install -y redis-server
sudo sed -i 's/notify-keyspace-events ""/notify-keyspace-events AKE/' /etc/redis/redis.conf
sudo sed -ri 's/^# unixsocket/unixsocket/' /etc/redis/redis.conf
sudo sed -ri 's/^unixsocketperm .../unixsocketperm 777/' /etc/redis/redis.conf
sudo sed -ri 's/redis-server.sock/redis.sock/' /etc/redis/redis.conf
sudo service redis-server restart
sudo rm -rf /var/run/sswsyncd
sudo mkdir -m 755 /var/run/sswsyncd

# Install rsyslog
sudo apt-get install -y rsyslog
sudo service rsyslog start

# Install libyang
mkdir dep-libyang
cp /sonic/target/debs/bullseye/libyang-*.deb ./dep-libyang
cp /sonic/target/debs/bullseye/libyang_*.deb ./dep-libyang
sudo dpkg -i $(find ./dep-libyang -name "*.deb")
sudo rm -rf dep-libyang

# Create yang model folder
sudo rm -rf /usr/local/yang-models
sudo mkdir /usr/local/yang-models

# Install Pympler
sudo pip3 install Pympler==0.8

# Install .NET CORE
curl -sSL https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
sudo apt-add-repository https://packages.microsoft.com/debian/11/prod
sudo apt-get update
sudo apt-get install -y dotnet-sdk-6.0

# Install report tool
already_installed=`sudo dotnet tool list -g | grep dotnet-reportgenerator-globaltool || true`
if [[ $already_installed == "" ]]; then
    sudo dotnet tool install -g dotnet-reportgenerator-globaltool
fi

# Install diff cover tool
sudo pip3 install diff_cover
