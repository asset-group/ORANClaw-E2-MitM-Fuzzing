# makefile to build generated files

include ./asn1c/cpp/platform.mk

# include directories
OSROOTDIR = .$(PS)asn1c
LIBDIR  = $(OSROOTDIR)$(PS)cpp$(RTDIRSFX)$(PS)lib
RTSRCDIR = $(OSROOTDIR)$(PS)rtsrc
RTXSRCDIR = $(OSROOTDIR)$(PS)rtxsrc
PERSRCDIR = $(OSROOTDIR)$(PS)rtpersrc
SRCDIR = .$(PS)src
HFILESDIR = .$(PS)src
HFILES =  \
$(RTSRCDIR)$(PS)asn1type.h \
$(RTXSRCDIR)$(PS)osMacros.h \
$(RTXSRCDIR)$(PS)osSysTypes.h \
$(RTXSRCDIR)$(PS)rtxContext.h \
$(RTXSRCDIR)$(PS)rtxDList.h \
$(RTXSRCDIR)$(PS)rtxExternDefs.h \
$(RTXSRCDIR)$(PS)rtxCommonDefs.h \
$(RTXSRCDIR)$(PS)rtxStack.h \
$(RTSRCDIR)$(PS)asn1CppTypes.h \
$(PERSRCDIR)$(PS)asn1per.h \
$(PERSRCDIR)$(PS)asn1PerCppTypes.h

# compiler defs
CFLAGS = -c $(CVARS_) $(CFLAGS_) $(CBLDTYPE_) -D_TRACE
CCFLAGS = -c $(CVARS_) $(CCFLAGS_) $(CBLDTYPE_) -D_TRACE
IPATHS = -I$(SRCDIR) -I$(OSROOTDIR) -I$(HFILESDIR) -I$(RTSRCDIR) -I$(PERSRCDIR) $(IPATHS_)
LINKOPT = $(LINKOPT_)

# run-time libraries
LIBS = $(LIBDIR)/$(LIBPFX)asn1per$(A) $(LIBDIR)/$(LIBPFX)asn1json$(A) $(LIBDIR)/$(LIBPFX)asn1rt$(A)
LLIBS = $(LLPFX)asn1per$(LLAEXT) $(LLPFX)asn1json$(LLAEXT) $(LLPFX)asn1rt$(LLAEXT) $(LLSYS)
LPATHS = $(LPPFX)$(LIBDIR)

OBJECTS =  \
E2SM-KPM-IEs$(OBJ) \
E2SM-COMMON-IEs$(OBJ) \
E2SM-RC-IEs$(OBJ) \
E2AP-PDU-Descriptions$(OBJ) \
E2AP-PDU-Contents$(OBJ) \
E2AP-IEs$(OBJ) \
E2AP-CommonDataTypes$(OBJ)

ENCOBJECTS =  \
E2SM-KPM-IEsEnc$(OBJ) \
E2SM-COMMON-IEsEnc$(OBJ) \
E2SM-RC-IEsEnc$(OBJ) \
E2AP-PDU-DescriptionsEnc$(OBJ) \
E2AP-PDU-ContentsEnc$(OBJ) \
E2AP-IEsEnc$(OBJ) \
E2AP-CommonDataTypesEnc$(OBJ)

DECOBJECTS =  \
E2SM-KPM-IEsDec$(OBJ) \
E2SM-COMMON-IEsDec$(OBJ) \
E2SM-RC-IEsDec$(OBJ) \
E2AP-PDU-DescriptionsDec$(OBJ) \
E2AP-PDU-ContentsDec$(OBJ) \
E2AP-IEsDec$(OBJ) \
E2AP-CommonDataTypesDec$(OBJ)

PRTOBJECTS =  \
E2SM-KPM-IEsPrint$(OBJ) \
E2SM-COMMON-IEsPrint$(OBJ) \
E2SM-RC-IEsPrint$(OBJ) \
E2AP-PDU-DescriptionsPrint$(OBJ) \
E2AP-PDU-ContentsPrint$(OBJ) \
E2AP-IEsPrint$(OBJ) \
E2AP-CommonDataTypesPrint$(OBJ)

P2SOBJECTS =  \
E2SM-KPM-IEsPrtToStr$(OBJ) \
E2SM-COMMON-IEsPrtToStr$(OBJ) \
E2SM-RC-IEsPrtToStr$(OBJ) \
E2AP-PDU-DescriptionsPrtToStr$(OBJ) \
E2AP-PDU-ContentsPrtToStr$(OBJ) \
E2AP-IEsPrtToStr$(OBJ) \
E2AP-CommonDataTypesPrtToStr$(OBJ)

TESTOBJECTS =  \
E2SM-KPM-IEsTest$(OBJ) \
E2SM-COMMON-IEsTest$(OBJ) \
E2SM-RC-IEsTest$(OBJ) \
E2AP-PDU-DescriptionsTest$(OBJ) \
E2AP-PDU-ContentsTest$(OBJ) \
E2AP-IEsTest$(OBJ) \
E2AP-CommonDataTypesTest$(OBJ)

all : $(OBJECTS) $(ENCOBJECTS) $(DECOBJECTS) $(PRTOBJECTS)  \
$(P2SOBJECTS) $(TESTOBJECTS) reader$(EXE) server$(EXE) reader_json$(EXE)

READEROBJ_JSON = reader_json$(OBJ) $(OBJECTS) $(DECOBJECTS) $(ENCOBJECTS) \
 $(PRTOBJECTS) $(P2SOBJECTS)

READEROBJ = reader$(OBJ) $(OBJECTS) $(DECOBJECTS) $(ENCOBJECTS) \
 $(PRTOBJECTS) $(P2SOBJECTS)

reader$(EXE) : $(READEROBJ) $(LIBS)
	$(LINK) $(READEROBJ) $(LINKOPT) $(LPATHS) $(LLIBS)

reader_json$(EXE) : $(READEROBJ_JSON) $(LIBS)
	$(LINK) $(READEROBJ_JSON) $(LINKOPT) $(LPATHS) $(LLIBS) 

SERVEROBJ = server$(OBJ) $(OBJECTS) $(DECOBJECTS) $(ENCOBJECTS) $(PRTOBJECTS) \
 $(P2SOBJECTS)

server$(EXE) : $(SERVEROBJ) $(LIBS)
	$(LINK) $(SERVEROBJ) $(LINKOPT) $(LPATHS) $(LLIBS)

RWHFILES = $(HFILESDIR)$(PS)E2SM-KPM-IEs.h \
$(HFILESDIR)$(PS)E2SM-COMMON-IEs.h \
$(HFILESDIR)$(PS)E2SM-RC-IEs.h \
$(HFILESDIR)$(PS)E2AP-PDU-Descriptions.h \
$(HFILESDIR)$(PS)E2AP-PDU-Contents.h \
$(HFILESDIR)$(PS)E2AP-IEs.h \
$(HFILESDIR)$(PS)E2AP-CommonDataTypes.h \
$(HFILESDIR)$(PS)E2AP-Constants.h \
$(HFILESDIR)$(PS)E2AP-Containers.h \
$(HFILESDIR)$(PS)rtkey.h \
$(HFILES)
 
reader$(OBJ) : $(SRCDIR)$(PS)reader.cpp $(RWHFILES)
	$(CCC) -c $(CCFLAGS) $(IPATHS) $(SRCDIR)$(PS)reader.cpp

server$(OBJ) : $(SRCDIR)$(PS)server.cpp $(RWHFILES)
	$(CCC) -c $(CCFLAGS) $(IPATHS) $(SRCDIR)$(PS)server.cpp

reader_json$(OBJ) : $(SRCDIR)$(PS)reader_json.cpp $(RWHFILES)
	$(CCC) -c $(CCFLAGS) $(IPATHS) $(SRCDIR)$(PS)reader_json.cpp

# .cpp -> .obj rules
# common file rules
E2SM-KPM-IEs$(OBJ) : $(SRCDIR)$(PS)E2SM-KPM-IEs.cpp \
$(HFILESDIR)$(PS)E2SM-KPM-IEs.h \
$(HFILESDIR)$(PS)E2SM-COMMON-IEs.h \
$(HFILESDIR)$(PS)rtkey.h \
$(HFILES)
	$(CCC) $(CCFLAGS) -c $(IPATHS) $(SRCDIR)$(PS)E2SM-KPM-IEs.cpp

# decode file rules
E2SM-KPM-IEsDec$(OBJ) : $(SRCDIR)$(PS)E2SM-KPM-IEsDec.cpp \
$(HFILESDIR)$(PS)E2SM-KPM-IEs.h \
$(HFILESDIR)$(PS)E2SM-COMMON-IEs.h \
$(HFILESDIR)$(PS)rtkey.h \
$(HFILES)
	$(CCC) $(CCFLAGS) -c $(IPATHS) $(SRCDIR)$(PS)E2SM-KPM-IEsDec.cpp

# encode file rules
E2SM-KPM-IEsEnc$(OBJ) : $(SRCDIR)$(PS)E2SM-KPM-IEsEnc.cpp \
$(HFILESDIR)$(PS)E2SM-KPM-IEs.h \
$(HFILESDIR)$(PS)E2SM-COMMON-IEs.h \
$(HFILESDIR)$(PS)rtkey.h \
$(HFILES)
	$(CCC) $(CCFLAGS) -c $(IPATHS) $(SRCDIR)$(PS)E2SM-KPM-IEsEnc.cpp

# print file rules
E2SM-KPM-IEsPrint$(OBJ) : $(SRCDIR)$(PS)E2SM-KPM-IEsPrint.cpp \
$(HFILESDIR)$(PS)E2SM-KPM-IEs.h \
$(HFILESDIR)$(PS)E2SM-COMMON-IEs.h \
$(HFILESDIR)$(PS)rtkey.h \
$(HFILES)
	$(CCC) $(CCFLAGS) -c $(IPATHS) $(SRCDIR)$(PS)E2SM-KPM-IEsPrint.cpp

# print-to-string file rules
E2SM-KPM-IEsPrtToStr$(OBJ) : $(SRCDIR)$(PS)E2SM-KPM-IEsPrtToStr.cpp \
$(HFILESDIR)$(PS)E2SM-KPM-IEs.h \
$(HFILESDIR)$(PS)E2SM-COMMON-IEs.h \
$(HFILESDIR)$(PS)rtkey.h \
$(HFILES)
	$(CCC) $(CCFLAGS) -c $(IPATHS) $(SRCDIR)$(PS)E2SM-KPM-IEsPrtToStr.cpp

# test file rules
E2SM-KPM-IEsTest$(OBJ) : $(SRCDIR)$(PS)E2SM-KPM-IEsTest.cpp \
$(HFILESDIR)$(PS)E2SM-KPM-IEs.h \
$(HFILESDIR)$(PS)E2SM-COMMON-IEs.h \
$(HFILESDIR)$(PS)rtkey.h \
$(HFILES)
	$(CCC) $(CCFLAGS) -c $(IPATHS) $(SRCDIR)$(PS)E2SM-KPM-IEsTest.cpp

# common file rules
E2SM-COMMON-IEs$(OBJ) : $(SRCDIR)$(PS)E2SM-COMMON-IEs.cpp \
$(HFILESDIR)$(PS)E2SM-COMMON-IEs.h \
$(HFILESDIR)$(PS)rtkey.h \
$(HFILES)
	$(CCC) $(CCFLAGS) -c $(IPATHS) $(SRCDIR)$(PS)E2SM-COMMON-IEs.cpp

# decode file rules
E2SM-COMMON-IEsDec$(OBJ) : $(SRCDIR)$(PS)E2SM-COMMON-IEsDec.cpp \
$(HFILESDIR)$(PS)E2SM-COMMON-IEs.h \
$(HFILESDIR)$(PS)rtkey.h \
$(HFILES)
	$(CCC) $(CCFLAGS) -c $(IPATHS) $(SRCDIR)$(PS)E2SM-COMMON-IEsDec.cpp

# encode file rules
E2SM-COMMON-IEsEnc$(OBJ) : $(SRCDIR)$(PS)E2SM-COMMON-IEsEnc.cpp \
$(HFILESDIR)$(PS)E2SM-COMMON-IEs.h \
$(HFILESDIR)$(PS)rtkey.h \
$(HFILES)
	$(CCC) $(CCFLAGS) -c $(IPATHS) $(SRCDIR)$(PS)E2SM-COMMON-IEsEnc.cpp

# print file rules
E2SM-COMMON-IEsPrint$(OBJ) : $(SRCDIR)$(PS)E2SM-COMMON-IEsPrint.cpp \
$(HFILESDIR)$(PS)E2SM-COMMON-IEs.h \
$(HFILESDIR)$(PS)rtkey.h \
$(HFILES)
	$(CCC) $(CCFLAGS) -c $(IPATHS) $(SRCDIR)$(PS)E2SM-COMMON-IEsPrint.cpp

# print-to-string file rules
E2SM-COMMON-IEsPrtToStr$(OBJ) : $(SRCDIR)$(PS)E2SM-COMMON-IEsPrtToStr.cpp \
$(HFILESDIR)$(PS)E2SM-COMMON-IEs.h \
$(HFILESDIR)$(PS)rtkey.h \
$(HFILES)
	$(CCC) $(CCFLAGS) -c $(IPATHS) $(SRCDIR)$(PS)E2SM-COMMON-IEsPrtToStr.cpp

# test file rules
E2SM-COMMON-IEsTest$(OBJ) : $(SRCDIR)$(PS)E2SM-COMMON-IEsTest.cpp \
$(HFILESDIR)$(PS)E2SM-COMMON-IEs.h \
$(HFILESDIR)$(PS)rtkey.h \
$(HFILES)
	$(CCC) $(CCFLAGS) -c $(IPATHS) $(SRCDIR)$(PS)E2SM-COMMON-IEsTest.cpp

# common file rules
E2SM-RC-IEs$(OBJ) : $(SRCDIR)$(PS)E2SM-RC-IEs.cpp \
$(HFILESDIR)$(PS)E2SM-RC-IEs.h \
$(HFILESDIR)$(PS)E2SM-COMMON-IEs.h \
$(HFILESDIR)$(PS)rtkey.h \
$(HFILES)
	$(CCC) $(CCFLAGS) -c $(IPATHS) $(SRCDIR)$(PS)E2SM-RC-IEs.cpp

# decode file rules
E2SM-RC-IEsDec$(OBJ) : $(SRCDIR)$(PS)E2SM-RC-IEsDec.cpp \
$(HFILESDIR)$(PS)E2SM-RC-IEs.h \
$(HFILESDIR)$(PS)E2SM-COMMON-IEs.h \
$(HFILESDIR)$(PS)rtkey.h \
$(HFILES)
	$(CCC) $(CCFLAGS) -c $(IPATHS) $(SRCDIR)$(PS)E2SM-RC-IEsDec.cpp

# encode file rules
E2SM-RC-IEsEnc$(OBJ) : $(SRCDIR)$(PS)E2SM-RC-IEsEnc.cpp \
$(HFILESDIR)$(PS)E2SM-RC-IEs.h \
$(HFILESDIR)$(PS)E2SM-COMMON-IEs.h \
$(HFILESDIR)$(PS)rtkey.h \
$(HFILES)
	$(CCC) $(CCFLAGS) -c $(IPATHS) $(SRCDIR)$(PS)E2SM-RC-IEsEnc.cpp

# print file rules
E2SM-RC-IEsPrint$(OBJ) : $(SRCDIR)$(PS)E2SM-RC-IEsPrint.cpp \
$(HFILESDIR)$(PS)E2SM-RC-IEs.h \
$(HFILESDIR)$(PS)E2SM-COMMON-IEs.h \
$(HFILESDIR)$(PS)rtkey.h \
$(HFILES)
	$(CCC) $(CCFLAGS) -c $(IPATHS) $(SRCDIR)$(PS)E2SM-RC-IEsPrint.cpp

# print-to-string file rules
E2SM-RC-IEsPrtToStr$(OBJ) : $(SRCDIR)$(PS)E2SM-RC-IEsPrtToStr.cpp \
$(HFILESDIR)$(PS)E2SM-RC-IEs.h \
$(HFILESDIR)$(PS)E2SM-COMMON-IEs.h \
$(HFILESDIR)$(PS)rtkey.h \
$(HFILES)
	$(CCC) $(CCFLAGS) -c $(IPATHS) $(SRCDIR)$(PS)E2SM-RC-IEsPrtToStr.cpp

# test file rules
E2SM-RC-IEsTest$(OBJ) : $(SRCDIR)$(PS)E2SM-RC-IEsTest.cpp \
$(HFILESDIR)$(PS)E2SM-RC-IEs.h \
$(HFILESDIR)$(PS)E2SM-COMMON-IEs.h \
$(HFILESDIR)$(PS)rtkey.h \
$(HFILES)
	$(CCC) $(CCFLAGS) -c $(IPATHS) $(SRCDIR)$(PS)E2SM-RC-IEsTest.cpp

# common file rules
E2AP-PDU-Descriptions$(OBJ) : $(SRCDIR)$(PS)E2AP-PDU-Descriptions.cpp \
$(HFILESDIR)$(PS)E2AP-PDU-Descriptions.h \
$(HFILESDIR)$(PS)E2AP-CommonDataTypes.h \
$(HFILESDIR)$(PS)E2AP-PDU-Contents.h \
$(HFILESDIR)$(PS)E2AP-Constants.h \
$(HFILESDIR)$(PS)rtkey.h \
$(HFILES)
	$(CCC) $(CCFLAGS) -c $(IPATHS) $(SRCDIR)$(PS)E2AP-PDU-Descriptions.cpp

# decode file rules
E2AP-PDU-DescriptionsDec$(OBJ) : $(SRCDIR)$(PS)E2AP-PDU-DescriptionsDec.cpp \
$(HFILESDIR)$(PS)E2AP-PDU-Descriptions.h \
$(HFILESDIR)$(PS)E2AP-CommonDataTypes.h \
$(HFILESDIR)$(PS)E2AP-PDU-Contents.h \
$(HFILESDIR)$(PS)E2AP-Constants.h \
$(HFILESDIR)$(PS)rtkey.h \
$(HFILES)
	$(CCC) $(CCFLAGS) -c $(IPATHS) $(SRCDIR)$(PS)E2AP-PDU-DescriptionsDec.cpp

# encode file rules
E2AP-PDU-DescriptionsEnc$(OBJ) : $(SRCDIR)$(PS)E2AP-PDU-DescriptionsEnc.cpp \
$(HFILESDIR)$(PS)E2AP-PDU-Descriptions.h \
$(HFILESDIR)$(PS)E2AP-CommonDataTypes.h \
$(HFILESDIR)$(PS)E2AP-PDU-Contents.h \
$(HFILESDIR)$(PS)E2AP-Constants.h \
$(HFILESDIR)$(PS)rtkey.h \
$(HFILES)
	$(CCC) $(CCFLAGS) -c $(IPATHS) $(SRCDIR)$(PS)E2AP-PDU-DescriptionsEnc.cpp

# print file rules
E2AP-PDU-DescriptionsPrint$(OBJ) : $(SRCDIR)$(PS)E2AP-PDU-DescriptionsPrint.cpp \
$(HFILESDIR)$(PS)E2AP-PDU-Descriptions.h \
$(HFILESDIR)$(PS)E2AP-CommonDataTypes.h \
$(HFILESDIR)$(PS)E2AP-PDU-Contents.h \
$(HFILESDIR)$(PS)E2AP-Constants.h \
$(HFILESDIR)$(PS)rtkey.h \
$(HFILES)
	$(CCC) $(CCFLAGS) -c $(IPATHS) $(SRCDIR)$(PS)E2AP-PDU-DescriptionsPrint.cpp

# print-to-string file rules
E2AP-PDU-DescriptionsPrtToStr$(OBJ) : $(SRCDIR)$(PS)E2AP-PDU-DescriptionsPrtToStr.cpp \
$(HFILESDIR)$(PS)E2AP-PDU-Descriptions.h \
$(HFILESDIR)$(PS)E2AP-CommonDataTypes.h \
$(HFILESDIR)$(PS)E2AP-PDU-Contents.h \
$(HFILESDIR)$(PS)E2AP-Constants.h \
$(HFILESDIR)$(PS)rtkey.h \
$(HFILES)
	$(CCC) $(CCFLAGS) -c $(IPATHS) $(SRCDIR)$(PS)E2AP-PDU-DescriptionsPrtToStr.cpp

# test file rules
E2AP-PDU-DescriptionsTest$(OBJ) : $(SRCDIR)$(PS)E2AP-PDU-DescriptionsTest.cpp \
$(HFILESDIR)$(PS)E2AP-PDU-Descriptions.h \
$(HFILESDIR)$(PS)E2AP-CommonDataTypes.h \
$(HFILESDIR)$(PS)E2AP-PDU-Contents.h \
$(HFILESDIR)$(PS)E2AP-Constants.h \
$(HFILESDIR)$(PS)rtkey.h \
$(HFILES)
	$(CCC) $(CCFLAGS) -c $(IPATHS) $(SRCDIR)$(PS)E2AP-PDU-DescriptionsTest.cpp

# common file rules
E2AP-PDU-Contents$(OBJ) : $(SRCDIR)$(PS)E2AP-PDU-Contents.cpp \
$(HFILESDIR)$(PS)E2AP-PDU-Contents.h \
$(HFILESDIR)$(PS)E2AP-IEs.h \
$(HFILESDIR)$(PS)E2AP-Containers.h \
$(HFILESDIR)$(PS)E2AP-Constants.h \
$(HFILESDIR)$(PS)E2AP-CommonDataTypes.h \
$(HFILESDIR)$(PS)rtkey.h \
$(HFILES)
	$(CCC) $(CCFLAGS) -c $(IPATHS) $(SRCDIR)$(PS)E2AP-PDU-Contents.cpp

# decode file rules
E2AP-PDU-ContentsDec$(OBJ) : $(SRCDIR)$(PS)E2AP-PDU-ContentsDec.cpp \
$(HFILESDIR)$(PS)E2AP-PDU-Contents.h \
$(HFILESDIR)$(PS)E2AP-IEs.h \
$(HFILESDIR)$(PS)E2AP-Containers.h \
$(HFILESDIR)$(PS)E2AP-Constants.h \
$(HFILESDIR)$(PS)E2AP-CommonDataTypes.h \
$(HFILESDIR)$(PS)rtkey.h \
$(HFILES)
	$(CCC) $(CCFLAGS) -c $(IPATHS) $(SRCDIR)$(PS)E2AP-PDU-ContentsDec.cpp

# encode file rules
E2AP-PDU-ContentsEnc$(OBJ) : $(SRCDIR)$(PS)E2AP-PDU-ContentsEnc.cpp \
$(HFILESDIR)$(PS)E2AP-PDU-Contents.h \
$(HFILESDIR)$(PS)E2AP-IEs.h \
$(HFILESDIR)$(PS)E2AP-Containers.h \
$(HFILESDIR)$(PS)E2AP-Constants.h \
$(HFILESDIR)$(PS)E2AP-CommonDataTypes.h \
$(HFILESDIR)$(PS)rtkey.h \
$(HFILES)
	$(CCC) $(CCFLAGS) -c $(IPATHS) $(SRCDIR)$(PS)E2AP-PDU-ContentsEnc.cpp

# print file rules
E2AP-PDU-ContentsPrint$(OBJ) : $(SRCDIR)$(PS)E2AP-PDU-ContentsPrint.cpp \
$(HFILESDIR)$(PS)E2AP-PDU-Contents.h \
$(HFILESDIR)$(PS)E2AP-IEs.h \
$(HFILESDIR)$(PS)E2AP-Containers.h \
$(HFILESDIR)$(PS)E2AP-Constants.h \
$(HFILESDIR)$(PS)E2AP-CommonDataTypes.h \
$(HFILESDIR)$(PS)rtkey.h \
$(HFILES)
	$(CCC) $(CCFLAGS) -c $(IPATHS) $(SRCDIR)$(PS)E2AP-PDU-ContentsPrint.cpp

# print-to-string file rules
E2AP-PDU-ContentsPrtToStr$(OBJ) : $(SRCDIR)$(PS)E2AP-PDU-ContentsPrtToStr.cpp \
$(HFILESDIR)$(PS)E2AP-PDU-Contents.h \
$(HFILESDIR)$(PS)E2AP-IEs.h \
$(HFILESDIR)$(PS)E2AP-Containers.h \
$(HFILESDIR)$(PS)E2AP-Constants.h \
$(HFILESDIR)$(PS)E2AP-CommonDataTypes.h \
$(HFILESDIR)$(PS)rtkey.h \
$(HFILES)
	$(CCC) $(CCFLAGS) -c $(IPATHS) $(SRCDIR)$(PS)E2AP-PDU-ContentsPrtToStr.cpp

# test file rules
E2AP-PDU-ContentsTest$(OBJ) : $(SRCDIR)$(PS)E2AP-PDU-ContentsTest.cpp \
$(HFILESDIR)$(PS)E2AP-PDU-Contents.h \
$(HFILESDIR)$(PS)E2AP-IEs.h \
$(HFILESDIR)$(PS)E2AP-Containers.h \
$(HFILESDIR)$(PS)E2AP-Constants.h \
$(HFILESDIR)$(PS)E2AP-CommonDataTypes.h \
$(HFILESDIR)$(PS)rtkey.h \
$(HFILES)
	$(CCC) $(CCFLAGS) -c $(IPATHS) $(SRCDIR)$(PS)E2AP-PDU-ContentsTest.cpp

# common file rules
E2AP-IEs$(OBJ) : $(SRCDIR)$(PS)E2AP-IEs.cpp \
$(HFILESDIR)$(PS)E2AP-IEs.h \
$(HFILESDIR)$(PS)E2AP-CommonDataTypes.h \
$(HFILESDIR)$(PS)E2AP-Constants.h \
$(HFILESDIR)$(PS)rtkey.h \
$(HFILES)
	$(CCC) $(CCFLAGS) -c $(IPATHS) $(SRCDIR)$(PS)E2AP-IEs.cpp

# decode file rules
E2AP-IEsDec$(OBJ) : $(SRCDIR)$(PS)E2AP-IEsDec.cpp \
$(HFILESDIR)$(PS)E2AP-IEs.h \
$(HFILESDIR)$(PS)E2AP-CommonDataTypes.h \
$(HFILESDIR)$(PS)E2AP-Constants.h \
$(HFILESDIR)$(PS)rtkey.h \
$(HFILES)
	$(CCC) $(CCFLAGS) -c $(IPATHS) $(SRCDIR)$(PS)E2AP-IEsDec.cpp

# encode file rules
E2AP-IEsEnc$(OBJ) : $(SRCDIR)$(PS)E2AP-IEsEnc.cpp \
$(HFILESDIR)$(PS)E2AP-IEs.h \
$(HFILESDIR)$(PS)E2AP-CommonDataTypes.h \
$(HFILESDIR)$(PS)E2AP-Constants.h \
$(HFILESDIR)$(PS)rtkey.h \
$(HFILES)
	$(CCC) $(CCFLAGS) -c $(IPATHS) $(SRCDIR)$(PS)E2AP-IEsEnc.cpp

# print file rules
E2AP-IEsPrint$(OBJ) : $(SRCDIR)$(PS)E2AP-IEsPrint.cpp \
$(HFILESDIR)$(PS)E2AP-IEs.h \
$(HFILESDIR)$(PS)E2AP-CommonDataTypes.h \
$(HFILESDIR)$(PS)E2AP-Constants.h \
$(HFILESDIR)$(PS)rtkey.h \
$(HFILES)
	$(CCC) $(CCFLAGS) -c $(IPATHS) $(SRCDIR)$(PS)E2AP-IEsPrint.cpp

# print-to-string file rules
E2AP-IEsPrtToStr$(OBJ) : $(SRCDIR)$(PS)E2AP-IEsPrtToStr.cpp \
$(HFILESDIR)$(PS)E2AP-IEs.h \
$(HFILESDIR)$(PS)E2AP-CommonDataTypes.h \
$(HFILESDIR)$(PS)E2AP-Constants.h \
$(HFILESDIR)$(PS)rtkey.h \
$(HFILES)
	$(CCC) $(CCFLAGS) -c $(IPATHS) $(SRCDIR)$(PS)E2AP-IEsPrtToStr.cpp

# test file rules
E2AP-IEsTest$(OBJ) : $(SRCDIR)$(PS)E2AP-IEsTest.cpp \
$(HFILESDIR)$(PS)E2AP-IEs.h \
$(HFILESDIR)$(PS)E2AP-CommonDataTypes.h \
$(HFILESDIR)$(PS)E2AP-Constants.h \
$(HFILESDIR)$(PS)rtkey.h \
$(HFILES)
	$(CCC) $(CCFLAGS) -c $(IPATHS) $(SRCDIR)$(PS)E2AP-IEsTest.cpp

# common file rules
E2AP-CommonDataTypes$(OBJ) : $(SRCDIR)$(PS)E2AP-CommonDataTypes.cpp \
$(HFILESDIR)$(PS)E2AP-CommonDataTypes.h \
$(HFILESDIR)$(PS)rtkey.h \
$(HFILES)
	$(CCC) $(CCFLAGS) -c $(IPATHS) $(SRCDIR)$(PS)E2AP-CommonDataTypes.cpp

# decode file rules
E2AP-CommonDataTypesDec$(OBJ) : $(SRCDIR)$(PS)E2AP-CommonDataTypesDec.cpp \
$(HFILESDIR)$(PS)E2AP-CommonDataTypes.h \
$(HFILESDIR)$(PS)rtkey.h \
$(HFILES)
	$(CCC) $(CCFLAGS) -c $(IPATHS) $(SRCDIR)$(PS)E2AP-CommonDataTypesDec.cpp

# encode file rules
E2AP-CommonDataTypesEnc$(OBJ) : $(SRCDIR)$(PS)E2AP-CommonDataTypesEnc.cpp \
$(HFILESDIR)$(PS)E2AP-CommonDataTypes.h \
$(HFILESDIR)$(PS)rtkey.h \
$(HFILES)
	$(CCC) $(CCFLAGS) -c $(IPATHS) $(SRCDIR)$(PS)E2AP-CommonDataTypesEnc.cpp

# print file rules
E2AP-CommonDataTypesPrint$(OBJ) : $(SRCDIR)$(PS)E2AP-CommonDataTypesPrint.cpp \
$(HFILESDIR)$(PS)E2AP-CommonDataTypes.h \
$(HFILESDIR)$(PS)rtkey.h \
$(HFILES)
	$(CCC) $(CCFLAGS) -c $(IPATHS) $(SRCDIR)$(PS)E2AP-CommonDataTypesPrint.cpp

# print-to-string file rules
E2AP-CommonDataTypesPrtToStr$(OBJ) : $(SRCDIR)$(PS)E2AP-CommonDataTypesPrtToStr.cpp \
$(HFILESDIR)$(PS)E2AP-CommonDataTypes.h \
$(HFILESDIR)$(PS)rtkey.h \
$(HFILES)
	$(CCC) $(CCFLAGS) -c $(IPATHS) $(SRCDIR)$(PS)E2AP-CommonDataTypesPrtToStr.cpp

# test file rules
E2AP-CommonDataTypesTest$(OBJ) : $(SRCDIR)$(PS)E2AP-CommonDataTypesTest.cpp \
$(HFILESDIR)$(PS)E2AP-CommonDataTypes.h \
$(HFILESDIR)$(PS)rtkey.h \
$(HFILES)
	$(CCC) $(CCFLAGS) -c $(IPATHS) $(SRCDIR)$(PS)E2AP-CommonDataTypesTest.cpp

# .asn -> .cpp .h rules
$(SRCDIR)/E2SM-KPM-IEsEnc.cpp \
$(SRCDIR)/E2SM-KPM-IEsDec.cpp \
$(SRCDIR)/E2SM-KPM-IEs.cpp \
$(SRCDIR)/E2SM-KPM-IEsPrint.cpp \
$(SRCDIR)/E2SM-KPM-IEsPrtToStr.cpp \
$(SRCDIR)/E2SM-KPM-IEsTest.cpp \
$(HFILESDIR)$(PS)E2SM-KPM-IEs.h \
$(SRCDIR)/E2SM-COMMON-IEsEnc.cpp \
$(SRCDIR)/E2SM-COMMON-IEsDec.cpp \
$(SRCDIR)/E2SM-COMMON-IEs.cpp \
$(SRCDIR)/E2SM-COMMON-IEsPrint.cpp \
$(SRCDIR)/E2SM-COMMON-IEsPrtToStr.cpp \
$(SRCDIR)/E2SM-COMMON-IEsTest.cpp \
$(HFILESDIR)$(PS)E2SM-COMMON-IEs.h \
$(SRCDIR)/E2SM-RC-IEsEnc.cpp \
$(SRCDIR)/E2SM-RC-IEsDec.cpp \
$(SRCDIR)/E2SM-RC-IEs.cpp \
$(SRCDIR)/E2SM-RC-IEsPrint.cpp \
$(SRCDIR)/E2SM-RC-IEsPrtToStr.cpp \
$(SRCDIR)/E2SM-RC-IEsTest.cpp \
$(HFILESDIR)$(PS)E2SM-RC-IEs.h \
$(SRCDIR)/E2AP-PDU-DescriptionsEnc.cpp \
$(SRCDIR)/E2AP-PDU-DescriptionsDec.cpp \
$(SRCDIR)/E2AP-PDU-Descriptions.cpp \
$(SRCDIR)/E2AP-PDU-DescriptionsPrint.cpp \
$(SRCDIR)/E2AP-PDU-DescriptionsPrtToStr.cpp \
$(SRCDIR)/E2AP-PDU-DescriptionsTest.cpp \
$(HFILESDIR)$(PS)E2AP-PDU-Descriptions.h \
$(SRCDIR)/E2AP-PDU-ContentsEnc.cpp \
$(SRCDIR)/E2AP-PDU-ContentsDec.cpp \
$(SRCDIR)/E2AP-PDU-Contents.cpp \
$(SRCDIR)/E2AP-PDU-ContentsPrint.cpp \
$(SRCDIR)/E2AP-PDU-ContentsPrtToStr.cpp \
$(SRCDIR)/E2AP-PDU-ContentsTest.cpp \
$(HFILESDIR)$(PS)E2AP-PDU-Contents.h \
$(SRCDIR)/E2AP-IEsEnc.cpp \
$(SRCDIR)/E2AP-IEsDec.cpp \
$(SRCDIR)/E2AP-IEs.cpp \
$(SRCDIR)/E2AP-IEsPrint.cpp \
$(SRCDIR)/E2AP-IEsPrtToStr.cpp \
$(SRCDIR)/E2AP-IEsTest.cpp \
$(HFILESDIR)$(PS)E2AP-IEs.h \
$(SRCDIR)/E2AP-CommonDataTypesEnc.cpp \
$(SRCDIR)/E2AP-CommonDataTypesDec.cpp \
$(SRCDIR)/E2AP-CommonDataTypes.cpp \
$(SRCDIR)/E2AP-CommonDataTypesPrint.cpp \
$(SRCDIR)/E2AP-CommonDataTypesPrtToStr.cpp \
$(SRCDIR)/E2AP-CommonDataTypesTest.cpp \
$(HFILESDIR)$(PS)E2AP-CommonDataTypes.h \
$(HFILESDIR)$(PS)E2AP-Constants.h \
$(HFILESDIR)$(PS)E2AP-Containers.h \
$(HFILESDIR)$(PS)rtkey.h \
\
: ./asn1files/E2SM-KPM-v05.00.asn ./asn1files/asn_flexric/e2sm_rc_v1_03_modified.asn ./asn1files/asn_flexric/e42ap_v2_03.asn $(OSROOTDIR)$(PS)bin$(PS)asn1c$(EXE)
	$(OSROOTDIR)$(PS)bin$(PS)asn1c ./asn1files/E2SM-KPM-v05.00.asn ./asn1files/asn_flexric/e2sm_rc_v1_03_modified.asn ./asn1files/asn_flexric/e42ap_v2_03.asn -cpp -json -per -depends -events -oh $(HFILESDIR) -i asn1files -i asn1files/asn_flexric -o ./src -genprint -printformat details -genprttostr -printformat details -stream -table-unions -gentest -trace

clean:
	$(RM) $(SRCDIR)$(PS)E2SM-KPM-IEsEnc.cpp
	$(RM) $(SRCDIR)$(PS)E2SM-KPM-IEsDec.cpp
	$(RM) $(SRCDIR)$(PS)E2SM-KPM-IEs.cpp
	$(RM) $(SRCDIR)$(PS)E2SM-KPM-IEsPrint.cpp
	$(RM) $(SRCDIR)$(PS)E2SM-KPM-IEsPrtToStr.cpp
	$(RM) $(SRCDIR)$(PS)E2SM-KPM-IEsTest.cpp
	$(RM) $(HFILESDIR)$(PS)E2SM-KPM-IEs.h
	$(RM) $(SRCDIR)$(PS)E2SM-COMMON-IEsEnc.cpp
	$(RM) $(SRCDIR)$(PS)E2SM-COMMON-IEsDec.cpp
	$(RM) $(SRCDIR)$(PS)E2SM-COMMON-IEs.cpp
	$(RM) $(SRCDIR)$(PS)E2SM-COMMON-IEsPrint.cpp
	$(RM) $(SRCDIR)$(PS)E2SM-COMMON-IEsPrtToStr.cpp
	$(RM) $(SRCDIR)$(PS)E2SM-COMMON-IEsTest.cpp
	$(RM) $(HFILESDIR)$(PS)E2SM-COMMON-IEs.h
	$(RM) $(SRCDIR)$(PS)E2SM-RC-IEsEnc.cpp
	$(RM) $(SRCDIR)$(PS)E2SM-RC-IEsDec.cpp
	$(RM) $(SRCDIR)$(PS)E2SM-RC-IEs.cpp
	$(RM) $(SRCDIR)$(PS)E2SM-RC-IEsPrint.cpp
	$(RM) $(SRCDIR)$(PS)E2SM-RC-IEsPrtToStr.cpp
	$(RM) $(SRCDIR)$(PS)E2SM-RC-IEsTest.cpp
	$(RM) $(HFILESDIR)$(PS)E2SM-RC-IEs.h
	$(RM) $(SRCDIR)$(PS)E2AP-PDU-DescriptionsEnc.cpp
	$(RM) $(SRCDIR)$(PS)E2AP-PDU-DescriptionsDec.cpp
	$(RM) $(SRCDIR)$(PS)E2AP-PDU-Descriptions.cpp
	$(RM) $(SRCDIR)$(PS)E2AP-PDU-DescriptionsPrint.cpp
	$(RM) $(SRCDIR)$(PS)E2AP-PDU-DescriptionsPrtToStr.cpp
	$(RM) $(SRCDIR)$(PS)E2AP-PDU-DescriptionsTest.cpp
	$(RM) $(HFILESDIR)$(PS)E2AP-PDU-Descriptions.h
	$(RM) $(SRCDIR)$(PS)E2AP-PDU-ContentsEnc.cpp
	$(RM) $(SRCDIR)$(PS)E2AP-PDU-ContentsDec.cpp
	$(RM) $(SRCDIR)$(PS)E2AP-PDU-Contents.cpp
	$(RM) $(SRCDIR)$(PS)E2AP-PDU-ContentsPrint.cpp
	$(RM) $(SRCDIR)$(PS)E2AP-PDU-ContentsPrtToStr.cpp
	$(RM) $(SRCDIR)$(PS)E2AP-PDU-ContentsTest.cpp
	$(RM) $(HFILESDIR)$(PS)E2AP-PDU-Contents.h
	$(RM) $(SRCDIR)$(PS)E2AP-IEsEnc.cpp
	$(RM) $(SRCDIR)$(PS)E2AP-IEsDec.cpp
	$(RM) $(SRCDIR)$(PS)E2AP-IEs.cpp
	$(RM) $(SRCDIR)$(PS)E2AP-IEsPrint.cpp
	$(RM) $(SRCDIR)$(PS)E2AP-IEsPrtToStr.cpp
	$(RM) $(SRCDIR)$(PS)E2AP-IEsTest.cpp
	$(RM) $(HFILESDIR)$(PS)E2AP-IEs.h
	$(RM) $(SRCDIR)$(PS)E2AP-CommonDataTypesEnc.cpp
	$(RM) $(SRCDIR)$(PS)E2AP-CommonDataTypesDec.cpp
	$(RM) $(SRCDIR)$(PS)E2AP-CommonDataTypes.cpp
	$(RM) $(SRCDIR)$(PS)E2AP-CommonDataTypesPrint.cpp
	$(RM) $(SRCDIR)$(PS)E2AP-CommonDataTypesPrtToStr.cpp
	$(RM) $(SRCDIR)$(PS)E2AP-CommonDataTypesTest.cpp
	$(RM) $(HFILESDIR)$(PS)E2AP-CommonDataTypes.h
	$(RM) $(HFILESDIR)$(PS)E2AP-Constants.h
	$(RM) $(HFILESDIR)$(PS)E2AP-Containers.h
	$(RM) $(HFILESDIR)$(PS)rtkey.h
	$(RM) $(HFILESDIR)$(PS)rtkey.h
	$(RM) *$(OBJ)
	$(RM) *~
	$(RM) reader$(EXE)
	$(RM_MSVC_FILES)
