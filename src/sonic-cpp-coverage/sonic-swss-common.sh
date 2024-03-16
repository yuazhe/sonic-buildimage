# Build target to make it auto install dependencies
set -ex
cd /sonic
rm -f target/debs/bullseye/libswsscommon_1.0.0_amd64.deb
make -f slave.mk target/debs/bullseye/libswsscommon_1.0.0_amd64.deb-install
cd /sonic/src/sonic-swss-common

# Clean previous coverage data if any
sudo rm -rf $(find . -name "*.gcda")
sudo rm -rf $(find . -name "*.gcno")
sudo git clean -d -f

# Build target
rm ../*.deb || true
./autogen.sh
make clean || true
fakeroot debian/rules DEB_CONFIGURE_EXTRA_FLAGS='--enable-code-coverage' DEB_BUILD_PROFILES=nopython2 CFLAGS="" CXXFLAGS="--coverage -fprofile-abs-path" LDFLAGS="--coverage -fprofile-abs-path" binary
mv ../*.deb .

# Install target debs
sudo dpkg -i libswsscommon_*.deb
sudo dpkg -i libswsscommon-dev_*.deb
sudo dpkg -i python3-swsscommon_*.deb

# Run tests and collect coverage data
redis-cli FLUSHALL
./tests/tests
redis-cli FLUSHALL
pytest-3 --cov=. --cov-report=xml
[ -f coverage.xml ] && mv coverage.xml tests/coverage.xml
gcovr -r ./ -e ".*/swsscommon_wrap.cpp" -e=tests --exclude-unreachable-branches --exclude-throw-branches --gcov-ignore-parse-errors -x --xml-pretty  -o coverage.xml
make -C goext
redis-cli FLUSHALL
make -C goext check

# Generate HTML full report
sudo /root/.dotnet/tools/reportgenerator -reports:"./coverage.xml" -targetdir:"htmlcov" -reporttypes:Html
echo "sonic-swss-common full coverage report is at src/sonic-swss-common/htmlcov"

# Generate diff report
diff-cover coverage.xml --html-report report.html --compare-branch=origin/master --fail-under=80
echo "sonic-swss-common diff coverage report is at src/sonic-swss-common/report.html"
