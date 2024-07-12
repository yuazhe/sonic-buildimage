# Build target to make it auto install dependencies
cd /sonic
make -f slave.mk target/debs/bullseye/swss_1.0.0_amd64.deb

# Build with gcov flag
cd /sonic/src/sonic-swss
rm ../*.deb || true
export ENABLE_GCOV=y
./autogen.sh
dpkg-buildpackage -us -uc -b -j$(nproc) && cp ../*.deb .

make check
[ -f coverage.xml ] && mv coverage.xml tests/coverage.xml

# Run tests and collect coverage data
gcovr -r ./ -e=tests --exclude-unreachable-branches --exclude-throw-branches --gcov-ignore-parse-errors -x --xml-pretty  -o coverage.xml
echo "sonic-swss-common full coverage report is at src/sonic-swss-common/htmlcov"
 
# # Generate HTML full report
sudo /root/.dotnet/tools/reportgenerator -reports:"./coverage.xml" -targetdir:"htmlcov" -reporttypes:Html
echo "sonic-swss full coverage report is at src/sonic-swss/htmlcov"

# Generate diff report
diff-cover coverage.xml --html-report report.html --compare-branch=origin/master --fail-under=80
echo "sonic-swss diff coverage report is at src/sonic-swss/report.html"
