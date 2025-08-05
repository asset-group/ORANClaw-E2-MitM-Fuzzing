#!/usr/bin/env bash

# ./asn1c/bin/asn1c \
# asn1files/E2SM-KPM-v05.00.asn  \
# asn1files/asn_flexric/e2sm_rc_v1_03_modified.asn  \
# asn1files/asn_flexric/e42ap_v2_03.asn -genTest \
# -per -json -w32 -server -depends -events -genPrtToStr \
# -list -reader -trace -c++ -print -prtfmt details \
# -srcdir src -make Makefile -w32 -table-unions -stream \
# #-usepdu E2AP-PDU 
# -pdu all

./asn1c/bin/asn1c \
asn1files/E2SM-KPM-v05.00.asn \
asn1files/asn_flexric/e2sm_rc_v1_03_modified.asn \
asn1files/asn_flexric/e42ap_v2_03.asn -genTest \
-per -json -w32 -server -depends -events -genPrtToStr \
-list -reader -trace -c++ -print -prtfmt details \
-srcdir src -make Makefile -w32 -table-unions -stream -pdu all
#-usepdu E2AP-PDU 

#./asn1c/bin/asn1c \
#asn1files/e2ap-v05.00.00.asn asn1files/E2SM-KPM-v05.00.asn  \
#asn1files/asn_flexric/e2sm_rc_v1_03_modified.asn 

# ./asn1c/bin/asn1c asn1files/asn_flexric/e42ap_v3_01.asn  \ 
# asn1files/E2SM-KPM-v05.00.asn asn1files/asn_flexric/e2sm_rc_v1_03_modified.asn -genTest \
# -per -json -w32 -depends -events - genPrtToStr \
# -list -reader -client -trace -c++ -print -prtfmt details \
# -srcdir src  -make Makefile -w32 -table-unions -stream -pdu all \
# #-usepdu E2AP-PDU 

# ./asn1c/bin/asn1c asn1files/asn_flexric/e42ap_v2_03.asn -per -json -w32 -events -genPrtToStr \
#  -list -reader -trace -c++ -depends -print -prtfmt details -srcdir src  -make Makefile -w32 \
#  -table-unions -stream -pdu all #-usepdu E2AP-PDU 


#sleep 1

#sed -i '
#27s/$/ -m32/
#28s/$/ -m32/
#30s/$/ -m32/
#' Makefile

make -j8 