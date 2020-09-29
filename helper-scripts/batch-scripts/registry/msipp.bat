@echo off
REG QUERY "HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\MSIPC" /v MSIPP-MK > msipp-mk
REG QUERY "HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\MSIPC" /v MSIPP-SK > msipp-sk
