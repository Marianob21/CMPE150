#!/usr/bin/env bash
awk 'FNR%2==0 {print FILENAME":"$0}' *