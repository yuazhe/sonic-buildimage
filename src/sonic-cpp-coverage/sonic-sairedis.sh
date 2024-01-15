# Build target to make it auto install dependencies
set -ex
cd /sonic
#rm -f target/debs/bullseye/syncd_1.0.0_amd64.deb
make -f slave.mk target/debs/bullseye/syncd_1.0.0_amd64.deb-install
cd /sonic/src/sonic-sairedis

# Install sonic-swss-common
sudo dpkg -i /sonic/target/debs/bullseye/libswsscommon_1.0.0_amd64.deb
sudo dpkg -i /sonic/target/debs/bullseye/libswsscommon-dev_1.0.0_amd64.deb

# Build target
rm ../*.deb || true
./autogen.sh
extraflags='--enable-code-coverage'
DEB_BUILD_OPTIONS=nocheck DEB_CONFIGURE_EXTRA_FLAGS=$extraflags dpkg-buildpackage -us -uc -b -Psyncd,vs,nopython2 -j$(nproc)
mv ../*.deb .

# Update rsyslog.conf
sudo cp azsyslog.conf /etc/rsyslog.conf
sudo service rsyslog restart

# Generate coverage.xml
sudo setcap "cap_sys_time=eip" syncd/.libs/syncd_tests
sudo setcap "cap_dac_override,cap_ipc_lock,cap_ipc_owner,cap_sys_time=eip" unittest/syncd/.libs/tests
redis-cli FLUSHALL
make check
gcovr --version
find SAI/meta -name "*.gc*" | xargs rm -vf
gcov_dirs=$(find . -path "*.libs*gcda" | xargs dirname | sort -u |  cut -c"3-")
for dir in ${gcov_dirs}; do
    source_dir=$(dirname $dir)
    output_file="coverage-$source_dir.json"
    gcovr --exclude-unreachable-branches --json-pretty -o $output_file --object-directory $source_dir $dir
done
gcovr -r ./ -e ".*/SAI/.*" -e ".+/json.hpp" -e "swss/.+" -e ".*/.libs/.*" -e ".*/debian/.*" --exclude-unreachable-branches --json-pretty -o coverage-all.json
gcovr -a "coverage-*.json" -x --xml-pretty -o coverage.xml

# Generate HTML full report
sudo /root/.dotnet/tools/reportgenerator -reports:"./coverage.xml" -targetdir:"htmlcov" -reporttypes:Html
echo "sonic-sairedis full coverage report is at src/sonic-sairedis/htmlcov"

# Generate diff report
diff-cover coverage.xml --html-report report.html --compare-branch=origin/master --fail-under=80
echo "sonic-sairedis diff coverage report is at src/sonic-sairedis/report.html"
