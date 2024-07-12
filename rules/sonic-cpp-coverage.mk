# Generate code coverage report for cpp project. Currently support:
#     1. sonic-swss-common
#     2. sonic-sairedis
#     3. sonic-swss

sonic-coverage-tools:
	/bin/bash $(BUILD_WORKDIR)/src/sonic-cpp-coverage/install-tools.sh

sonic-swss-common-coverage: sonic-coverage-tools
	/bin/bash $(BUILD_WORKDIR)/src/sonic-cpp-coverage/sonic-swss-common.sh

sonic-sairedis-coverage: sonic-coverage-tools
	/bin/bash $(BUILD_WORKDIR)/src/sonic-cpp-coverage/sonic-sairedis.sh

sonic-swss-coverage: sonic-coverage-tools
	/bin/bash $(BUILD_WORKDIR)/src/sonic-cpp-coverage/sonic-swss.sh
