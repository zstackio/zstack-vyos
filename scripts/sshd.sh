#!/bin/bash

sudo service ssh status || sudo service ssh restart
sudo service rsyslog status || sudo service rsyslog restart
