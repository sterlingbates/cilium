FROM golang:1.18

RUN install -m 0755 -d /etc/apt/keyrings
RUN curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
RUN chmod a+r /etc/apt/keyrings/docker.gpg && \
    oscodename=$(. /etc/os-release && echo "$VERSION_CODENAME") && \
    osarch=$(dpkg --print-architecture) && \
    echo "deb [arch="${osarch}" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian ${oscodename} stable" > /etc/apt/sources.list.d/docker.list && \
    apt-get update

RUN apt-get install -y ca-certificates curl gnupg
RUN apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
RUN apt-get install -y clang llvm docker.io

RUN mkdir -p /usr/src/app/cilium
COPY . /usr/src/app/cilium
WORKDIR /usr/src/app/cilium

RUN go mod download
RUN go mod verify
