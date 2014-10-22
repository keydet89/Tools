@echo off
REM Batch file to automate parsing Windows Event Records
REM using LogParser and evtxparse
REM
REM
REM History
REM   20120608 - created
REM
REM Usage
REM   wevtx.bat g:\case\evtx\*.evtx g:\case\events.txt
REM
REM Author H. Carvey, keydet89@yahoo.com
logparser -i:evt -o:csv "Select RecordNumber,TO_UTCTIME(TimeGenerated),EventID,SourceName,ComputerName,SID,Strings from %1" > wevtx_tmp.txt
evtxparse wevtx_tmp.txt >> %2
del wevtx_tmp.txt