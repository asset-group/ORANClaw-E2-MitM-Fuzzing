#!/usr/bin/env bash


./scripts/open5gs-dbctl.sh add_ue_with_apn 999700000000001 fec86ba6eb707ed08905757b1bb44b8f c42449363bbad02b66d16bc975d77cc1 internet
./scripts/open5gs-dbctl.sh add_ue_with_apn 999700000000002 fec86ba6eb707ed08905757b1bb44b8f c42449363bbad02b66d16bc975d77cc1 internet 
./scripts/open5gs-dbctl.sh add_ue_with_apn 999700000000003 fec86ba6eb707ed08905757b1bb44b8f c42449363bbad02b66d16bc975d77cc1 internet 
./scripts/open5gs-dbctl.sh add_ue_with_apn 999700000000004 fec86ba6eb707ed08905757b1bb44b8f c42449363bbad02b66d16bc975d77cc1 internet
./scripts/open5gs-dbctl.sh add_ue_with_apn 999700000000005 fec86ba6eb707ed08905757b1bb44b8f c42449363bbad02b66d16bc975d77cc1 internet

echo "Done!"