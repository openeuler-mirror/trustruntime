Name: agentsandbox-hook
Version: 0.1.0
Release: 1
License: Apache-2.0
Summary: AgentSandbox startContainer OCI hook

Requires: socat

%description
OCI runtime hook for AgentSandbox container lifecycle management.

%prep
cp -r %{_sourcedir}/agentsandbox/deploy/hook/* .

%install
mkdir -p %{buildroot}/usr/bin
install -m 755 start_container.sh %{buildroot}/usr/bin/
install -m 755 stop_container.sh %{buildroot}/usr/bin/

%files
/usr/bin/start_container.sh
/usr/bin/stop_container.sh
