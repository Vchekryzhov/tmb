# PROTOTYPE (THROWAWAY) test rig for the TMB sudo integration question -
# issue #1. Test-only users, per-run keys, configs and state. This is NOT
# production tooling and must never be installed on a real machine.
#
# NOTE ON SUDO: mainstream distro packages (ubuntu:24.04 sudo 1.9.15p5,
# debian:trixie 1.9.16p2, fedora:41, alpine:3.21 - all verified) are built
# WITHOUT --enable-python, so they ship no sudo_plugin_python.so. To test the
# Python APPROVAL plugin hook in REAL sudo, this image builds the official
# sudo 1.9.17p1 source tarball from sudo.ws with --enable-python. It installs
# under /usr/local (binary /usr/local/bin/sudo, plugins under
# /usr/local/libexec/sudo) and keeps reading /etc/sudo.conf + /etc/sudoers,
# so the distro sudoers policy stays in place.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
ARG SUDO_VERSION=1.9.17p1

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      sudo python3 python3-cryptography python3-dev ca-certificates \
      build-essential zlib1g-dev curl \
 && rm -rf /var/lib/apt/lists/*

RUN curl -fL "https://www.sudo.ws/dist/sudo-${SUDO_VERSION}.tar.gz" -o /tmp/sudo.tar.gz \
 && tar xf /tmp/sudo.tar.gz -C /tmp \
 && cd "/tmp/sudo-${SUDO_VERSION}" \
 && ./configure --enable-python --sysconfdir=/etc --without-sendmail \
 && make -j"$(nproc)" \
 && make install \
 && rm -rf /tmp/sudo.tar.gz "/tmp/sudo-${SUDO_VERSION}" \
 && apt-get purge -y build-essential curl \
 && apt-get autoremove -y \
 && test -f /usr/local/libexec/sudo/python_plugin.so \
 && /usr/local/bin/sudo --version | head -1

# test-only users: agent = TMB agent path (no sudo password, TMB-gated),
# viktor = human with classic password sudo (password is test-only too)
RUN useradd -m -s /bin/bash agent \
 && useradd -m -s /bin/bash viktor \
 && echo 'viktor:human-pass-1' | chpasswd

COPY assets/ /usr/local/tmb/

RUN chmod 0755 /usr/local/tmb/bin/probe /usr/local/tmb/bin/dangerous \
               /usr/local/tmb/bin/tmb-dispatch /usr/local/tmb/bin/fake-signer \
               /usr/local/tmb/bin/tmbkeygen /usr/local/tmb/bin/tmb-mkperm \
               /usr/local/tmb/bin/run-matrix \
 && chmod 0644 /usr/local/tmb/bin/script.py /usr/local/tmb/lib/*.py \
 && install -m 0440 -D /usr/local/tmb/etc/sudoers.tmb-proto /etc/sudoers.d/tmb-proto \
 && printf '\n# PROTOTYPE TMB test-only approval plugin (throwaway)\nPlugin python_approval /usr/local/libexec/sudo/python_plugin.so ModulePath=/usr/local/tmb/lib/tmb_approval.py ClassName=TmbApprovalPlugin\n' >> /etc/sudo.conf \
 && mkdir -p /var/lib/tmb-proto/redeemed /var/lib/tmb-proto/artifacts /usr/local/tmb/etc \
 && visudo -cf /etc/sudoers.d/tmb-proto

CMD ["sleep", "infinity"]
