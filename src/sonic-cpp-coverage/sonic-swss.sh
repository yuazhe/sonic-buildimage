# Build target to make it auto install dependencies
cd /sonic/src/sonic-swss
make -f slave.mk target/debs/bullseye/swss_1.0.0_amd64.deb

# Build with gcov flag
rm ../*.deb || true
export ENABLE_GCOV=y
./autogen.sh
dpkg-buildpackage -us -uc -b -j16 && cp ../*.deb .
 

 
make check

[ -f coverage.xml ] && mv coverage.xml tests/coverage.xml


# Install gcovr and get xml output
git clone https://github.com/gcovr/gcovr.git
cd gcovr/
git checkout 5.2
sudo pip3 install setuptools
sudo python3 setup.py install
cd ..
sudo rm -rf gcovr
gcovr -r ./ -e=tests --exclude-unreachable-branches --exclude-throw-branches --gcov-ignore-parse-errors -x --xml-pretty  -o coverage.xml
 
# Install tools and generatereport
curl -sSL https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
sudo apt-add-repository https://packages.microsoft.com/debian/11/prod
sudo apt-get update
sudo apt-get install -y dotnet-sdk-7.0
sudo dotnet tool install -g dotnet-reportgenerator-globaltool
sudo /root/.dotnet/tools/reportgenerator -reports:"./coverage.xml" -targetdir:"htmlcov" -reporttypes:Html
