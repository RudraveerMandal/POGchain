ARG DISTRO
FROM ubuntu:${DISTRO}
# We need to repeat ARG here to make it available inside build context
# See https://docs.docker.com/engine/reference/builder/#understand-how-arg-and-from-interact
ARG DISTRO

MAINTAINER Siddharth Suresh <siddharth@POGchain.org>

EXPOSE 11625
EXPOSE 11626

VOLUME /data
VOLUME /postgresql-unix-sockets

ADD setup /
RUN /setup

ARG POGchain_CORE_VERSION

#install POGchain
RUN wget -qO - https://apt.POGchain.org/SDF.asc | apt-key add -
RUN echo "deb https://apt.POGchain.org ${DISTRO} unstable" | tee -a /etc/apt/sources.list.d/SDF-unstable.list
RUN apt-get update && apt-get install -y POGchain=${POGchain_CORE_VERSION}

WORKDIR "/etc/POGchain"
ENTRYPOINT ["/usr/bin/POGchain"]
