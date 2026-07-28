FROM ubuntu:18.04

ENV PATH="${PATH}:/usr/local/lib/python3.6/dist-packages/bin"
ENV LC_CTYPE=C.UTF-8

RUN apt-get update && \
    apt-get install -y \
        gcc \
        git \
        python3 \
        python3-pip \
        ruby \
        sudo \
        tmux \
        vim \
        wget && \
    rm -rf /var/lib/apt/lists/*

# install pwndbg
WORKDIR /root

RUN git clone https://github.com/pwndbg/pwndbg

WORKDIR /root/pwndbg

RUN git checkout 2023.03.19
RUN ./setup.sh

# install pwntools
RUN pip3 install --upgrade pip
RUN pip3 install pwntools

# install one_gadget for Ruby 2.5
RUN gem install elftools -v 1.1.3 --no-document && \
    gem install one_gadget -v 1.9.0 --no-document

WORKDIR /root
