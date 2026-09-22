FROM ubuntu:22.04@sha256:0e0a0fc6d18feda9db1590da249ac93e8d5abfea8f4c3c0c849ce512b5ef8982

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        binutils=2.38-4ubuntu2.12 \
        binwalk=2.3.3+dfsg1-2 \
        bsdextrautils=2.37.2-4ubuntu3.5 \
        file=1:5.41-3ubuntu0.1 \
        g++=4:11.2.0-1ubuntu1 \
        p7zip-full=16.02+dfsg-8 \
        python3=3.10.6-1~22.04.1 \
        python3-dev=3.10.6-1~22.04.1 \
        python3-pip=22.0.2+dfsg-1ubuntu0.7 \
        python3-pefile=2021.9.3-1 \
        unzip=6.0-26ubuntu3.2 \
        upx-ucl=3.96-3 \
        xxd=2:8.2.3995-1ubuntu2.34 \
        yara=4.1.3-1build1 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 reverse \
    && useradd --uid 10001 --gid reverse --no-create-home --shell /usr/sbin/nologin reverse \
    && mkdir -p /opt/investigator/rules /workspace /tmp \
    && chown reverse:reverse /workspace /tmp

COPY reverse_sandbox/requirements.lock /opt/investigator/reverse-requirements.lock
RUN python3 -m pip install --no-cache-dir --require-hashes \
        -r /opt/investigator/reverse-requirements.lock \
    && chmod 0444 /opt/investigator/reverse-requirements.lock

COPY reverse_sandbox/broker.py /usr/local/bin/reverse-broker
COPY reverse_sandbox/stage.py /usr/local/bin/reverse-stage
COPY reverse_sandbox/pecheck.py /usr/local/bin/pecheck
COPY reverse_sandbox/pedisasm.py /usr/local/bin/pedisasm
COPY reverse_sandbox/minidump_core.py /usr/local/lib/investigator/minidump_core.py
COPY reverse_sandbox/minidump_info.py /usr/local/bin/minidump-info
COPY reverse_sandbox/minidump_extract.py /usr/local/bin/minidump-extract
COPY reverse_sandbox/dotnet_inspect.py /usr/local/bin/dotnet-inspect
COPY reverse_sandbox/elf_inspect.py /usr/local/bin/elf-inspect
COPY reverse_sandbox/lief_info.py /usr/local/bin/lief-info
COPY reverse_sandbox/pyinstaller_inspect.py /usr/local/bin/pyinstaller-inspect
COPY reverse_sandbox/python_tool_runner.py /usr/local/bin/python-tool-runner
COPY app/reverse/command_policy.py /usr/local/lib/investigator/reverse_policy.py
COPY reverse_sandbox/default.yar /opt/investigator/rules/default.yar

RUN sed -i 's/\r$//' /usr/local/bin/reverse-broker /usr/local/bin/reverse-stage /usr/local/bin/pecheck /usr/local/bin/pedisasm /usr/local/bin/minidump-info /usr/local/bin/minidump-extract /usr/local/bin/dotnet-inspect /usr/local/bin/elf-inspect /usr/local/bin/lief-info /usr/local/bin/pyinstaller-inspect /usr/local/bin/python-tool-runner \
    && chmod 0555 /usr/local/bin/reverse-broker /usr/local/bin/reverse-stage /usr/local/bin/pecheck /usr/local/bin/pedisasm /usr/local/bin/minidump-info /usr/local/bin/minidump-extract /usr/local/bin/dotnet-inspect /usr/local/bin/elf-inspect /usr/local/bin/lief-info /usr/local/bin/pyinstaller-inspect /usr/local/bin/python-tool-runner \
    && chmod 0444 /usr/local/lib/investigator/minidump_core.py \
    && chmod 0444 /usr/local/lib/investigator/reverse_policy.py \
    && chmod 0444 /opt/investigator/rules/default.yar

USER reverse:reverse
WORKDIR /workspace
ENV HOME=/tmp PATH=/usr/local/bin:/usr/bin:/bin PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0

CMD ["sleep", "infinity"]
