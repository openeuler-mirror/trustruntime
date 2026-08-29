Name: agentsandbox
Version: 0.1.0
Release: 1
License: Apache-2.0
Summary: AgentSandbox - Agent sandbox runtime with proxy and eBPF security

Requires: systemd
Requires: kata-runtime

%description
AgentSandbox provides isolated runtime for AI agents with HTTPS proxy,
eBPF container escape protection, and TOML configuration management.

%prep
cp -r %{_sourcedir}/agentsandbox/* .

%install
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}/usr/lib/agentsandbox
install -m 755 target/release/agentsandbox-controller %{buildroot}/usr/bin/
install -m 755 target/release/agentsandbox-proxy %{buildroot}/usr/bin/
install -m 644 deploy/vm/rootfs/agentsandbox.service %{buildroot}/usr/lib/systemd/system/
install -m 644 deploy/vm/rootfs/proxy.service %{buildroot}/usr/lib/systemd/system/
install -m 755 deploy/hook/start_container.sh %{buildroot}/usr/bin/
install -m 755 deploy/hook/stop_container.sh %{buildroot}/usr/bin/
install -m 644 deploy/hook/hook.json %{buildroot}/usr/lib/agentsandbox/
install -m 644 deploy/ca/ca.crt %{buildroot}/etc/agentsandbox/
install -m 600 deploy/ca/ca.key %{buildroot}/etc/agentsandbox/

%files
/usr/bin/agentsandbox-controller
/usr/bin/agentsandbox-proxy
/usr/bin/start_container.sh
/usr/bin/stop_container.sh
/usr/lib/agentsandbox/hook.json
/usr/lib/systemd/system/agentsandbox.service
/usr/lib/systemd/system/proxy.service
/etc/agentsandbox/ca.crt
%attr(600,root,root) /etc/agentsandbox/ca.key
