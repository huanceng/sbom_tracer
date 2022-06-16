#!/usr/bin/env bash

init() {
  if [[ "$(expr substr "$(uname -s)" 1 5)" == "MINGW" ]]; then
    echo "sbom_tracer does not support windows now"
    exit 1
  fi

  if [ -f /etc/redhat-release ]; then
    DISTRO="RedHat"
    PACKAGE_MANAGER_APP="yum"
  elif [ -f /etc/debian_version ]; then
    DISTRO="Debian"
    PACKAGE_MANAGER_APP="apt-get"
  else
    echo "unsupported linux version"
    exit 1
  fi
}

install_pip() {
  echo "======install pip begin======"
  PYTHON_FULL_VERSION=$(sudo python -V 2>&1 | awk '{print $2}')
  if [[ "${PYTHON_FULL_VERSION}" =~ "3" ]]; then
    PYTHON_MAJOR_VERSION="3"
  elif [[ "${PYTHON_FULL_VERSION}" =~ "2" ]]; then
    PYTHON_MAJOR_VERSION="2"
  else
    echo "python is not installed yet, please install python"
    exit 1
  fi

  if [ "${DISTRO}" == "RedHat" ]; then
    sudo ${PACKAGE_MANAGER_APP} -y install epel-release
  fi

  if [ ${PYTHON_MAJOR_VERSION} == "3" ]; then
    sudo ${PACKAGE_MANAGER_APP} -y install python3-pip
    sudo python -m pip install --upgrade pip
  else
    sudo ${PACKAGE_MANAGER_APP} -y install python-pip
    sudo python -m pip install --upgrade "pip<21.0"
  fi
  echo "======install pip success======"
}

install_sbom_tracer() {
  echo "======install sbom_tracer begin======"
  sudo python -m pip install wheel
  sudo python setup.py bdist_wheel
  sudo python -m pip uninstall -y sbom_tracer
  sudo python -m pip install dist/sbom_tracer-1.0.0-py*-none-any.whl

  if ! sudo sbom_tracer --help; then
    echo "install sbom_tracer error"
    exit 1
  fi
  echo "======install sbom_tracer success======"
}

install_bcc() {
  echo "======install bcc begin======"
  if [ "${DISTRO}" == "RedHat" ]; then
    sudo ${PACKAGE_MANAGER_APP} -y install gnutls bcc kernel-devel-$(uname -r) kernel-headers-$(uname -r)
  elif [ "${DISTRO}" == "Debian" ]; then
    sudo ${PACKAGE_MANAGER_APP} -y install gnutls-bin bpfcc-tools linux-headers-$(uname -r)
  fi

  if [ $? -ne 0 ]; then
    echo "install bcc error"
    exit 1
  fi

  echo "======install bcc success======"
}

DISTRO=""
PACKAGE_MANAGER_APP=""
init
install_pip
install_sbom_tracer
install_bcc
