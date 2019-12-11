##########################
# Sampath Kunapareddy    #
# sampath.a926@gmail.com #
##########################
#!/bin/bash
#set -x
INPUTDS=$1
ORACLE_HOME="/opt/oracle"
HOST=$(echo `hostname` | tr [A-Z] [a-z])
echo -e "\nPlease wait for 10 secs trying to retrive DOMAIN_HOME.... please provide manullay if asked\n"
SDOMHM=$(timeout 10 find ${ORACLE_HOME}/* -name "setDomainEnv.sh" 2>/dev/null | head -1)
. ${SDOMHM} &>/dev/null
TDOMHM=$(echo $DOMAIN_HOME)
if [[ -z $TDOMHM ]]; then
  echo -e "\n\n"
  read -p "FAILED obtaining DOMAIN_HOME, please provide as below: `echo $'\n\tEx: /opt/oracle/admin/soa_domain/aserver/soa_domain\n\t\t>'`" TDOMHM
  if [[ -f ${TDOMHM}/bin/setDomainEnv.sh ]]; then
    . ${TDOMHM}/bin/setDomainEnv.sh &>/dev/null
  else
    echo -e "\n\n ${TDOMHM}/bin/setDomainEnv.sh does not exist please verify...\n\n"
    exit 1
  fi
fi

mw_home() {              #MHME      #/opt/ dependency
  MOPS=$(find /opt/ -type f -maxdepth 4 -name "registry.xml" 2>/dev/null | sort -u)
  for i in $MOPS; do
    if [[ ! -z $(cat $i | grep -i "WebLogic Server") ]]; then MOP=$i; fi
  done
  if [[ ! -z $(echo $MOP | grep "inventory") ]]; then
    MHME=`echo ${MOP%/*/*}`
  else
    MHME=`echo ${MOP%/*}`
  fi
}

weblogic_home() {        #WHME      #Dependency MHME
  if [[ ! -z $MHME ]]; then
    WHMEs=$(find "$MHME" -type d -maxdepth 1 -iname "*wlserver*" 2>/dev/null | sort -u)
    for WH in $WHMEs; do
      if [[ -f "$WH/server/bin/setWLSEnv.sh" ]]; then WHME=$WH; fi
    done
    if [[ -z $WHME ]]; then WHME=$(cat $MOP | grep "WebLogic Server" | awk -F 'InstallDir=' '{print $2}' | cut -d '"' -f2 | grep -v "^$"); fi
  else
    WHME=""
  fi
}

mw_home
weblogic_home

DECRYPT() {
  PASS=$1
  . ${SDOMHM} &>/dev/null
  if [ -d "${WHME}/../oracle_common/common/bin" ]; then
    cd ${WHME}/../oracle_common/common/bin 2>/dev/null
  else
    cd ${WHME}/common/bin 2>/dev/null
  fi
  if [[ $? -eq 0 ]]; then
    echo "domain = sys.argv[1]" > ./decrypt.py
    echo "service = weblogic.security.internal.SerializedSystemIni.getEncryptionService(domain)" >> ./decrypt.py
    echo "encryption = weblogic.security.internal.encryption.ClearOrEncryptedService(service)" >> ./decrypt.py
    echo "print \"Weblogic Password is: \" + encryption.decrypt(sys.argv[2])" >> ./decrypt.py
    chmod 755 ./decrypt.py 2>/dev/null
    #cp /opt/sw/prd_middleware/MWDev_Test/ksampath/decrypt.py .
    if [[ -f $PASS ]]; then
      for pass in $(cat $TDOMHM/config/jdbc/encrypted_pswd); do
        ./wlst.sh decrypt.py "$TDOMHM" "$pass" 2>/dev/null | grep -i pass | cut -d ":" -f2 | awk '{$1=$1;print}' >> $TDOMHM/config/jdbc/decrypted_pswd
      done
    else
      ./wlst.sh decrypt.py "$TDOMHM" $PASS 2>/dev/null | grep -i pass | cut -d ":" -f2 | awk '{$1=$1;print}'
    fi
    rm ./decrypt.py
    rm -rf ./security
    cd $TDOMHM/config/jdbc
  else
    echo -e "\n\nNOT A VALID DOMAIN, NO WLST MODULE FOUND...\n"
    exit 1
  fi
}

REMOVE() {
  rm $TDOMHM/config/jdbc/decrypted_pswd $TDOMHM/config/jdbc/encrypted_pswd $TDOMHM/config/jdbc/results_wout_pswd $TDOMHM/config/jdbc/DS_OUT.csv &>/dev/null
}

REMOVE

if [ -z $INPUTDS ]; then
  clear
  echo -e "\n******PASSWORD DECRYPTION******\n"
  if [[ ! -z $(ls -d $TDOMHM/config/jdbc 2>/dev/null) ]]; then
    cd $TDOMHM/config/jdbc
    for i in $(ls *.xml); do if [[ ! -z $(cat $i | grep -i password | cut -d '>' -f2 | cut -d '<' -f1 | awk '{$1=$1;print}') ]]; then echo "  -> $i" ; fi; done
    echo -e "\nXML files from \"$TDOMHM/config/jdbc\" location..."
    echo -e "\n"
    echo -e "Please \e[1;32mPICK a DS(*.xml)\e[0m from above (or)\nENTER any \e[1;32mEncrypted password(AES**)\e[0m (or)\nComplete \e[1;32mpath of any .xml\e[0m file"
    echo -en "\n\t ->"; read INPUT
    #read -p "please PICK a DS(*.xml) from above (or) ENTER Encrypted password(AES**):" INPUT
    echo -e "\n"
  else
    echo -e "\n"
    read -p "No DataSources found so Please ENTER Encrypted password(AES**):" INPUT
    echo -e "\n"
  fi
  if [[ $INPUT == *.xml ]]; then
    DIUSER=$(cat $INPUT 2>/dev/null | grep -A1 user | tail -1 | cut -d '>' -f2 | cut -d '<' -f1 | awk '{$1=$1;print}')
    if [[ -z $DIUSER ]]; then DIUSER="please check manually..."; fi
     echo -e "        User : $DIUSER"
    DIPASS=$(DECRYPT $(cat $INPUT 2>/dev/null | grep -i password | cut -d '>' -f2 | cut -d '<' -f1 | awk '{$1=$1;print}'))
    if [[ -z $DIPASS ]]; then DIPASS="ERROR...ERROR...ERROR...ERROR...ERROR...ERROR...ERROR...ERROR..."; fi
    echo -en "    Password : $DIPASS\n"
    DIHOST=$(cat $INPUT 2>/dev/null | grep HOST | awk -F "HOST" '{print $2}' | cut -d ')' -f1 | cut -d'=' -f2 | awk '{$1=$1;print}')
    if [[ -z $DIHOST ]]; then
      DIHOST=$(cat $INPUT 2>/dev/null | awk -F '<url>' '{print $2}' | awk -F '</url>' '{print $1}' | grep -v "^$" | awk -F '@//' '{print $2}' | cut -d / -f1 | cut -d : -f1 | awk '{$1=$1;print}')
    elif [[ -z $DIHOST ]]; then
      DIHOST="please check manually..."
    fi
    echo -e "        Host : $DIHOST"
    DIPORT=$(cat $INPUT 2>/dev/null | grep PORT | awk -F "PORT" '{print $2}' | cut -d ')' -f1 | cut -d'=' -f2 | awk '{$1=$1;print}')
    if [[ -z $DIPORT ]]; then
      DIPORT=$(cat $INPUT 2>/dev/null | awk -F '<url>' '{print $2}' | awk -F '</url>' '{print $1}' | grep -v "^$" | awk -F '@//' '{print $2}' | cut -d / -f1 | cut -d : -f2 | awk '{$1=$1;print}')
    elif [[ -z $DIPORT ]]; then
      DIPORT="please check manually..."
    fi    
    echo -e "        Port : $DIPORT"
    DISNME=$(cat $INPUT 2>/dev/null | grep SERVICE_NAME | awk -F "SERVICE_NAME" '{print $2}' | cut -d ')' -f1 | cut -d'=' -f2 | awk '{$1=$1;print}')
    if [[ -z $DISNME ]]; then
      DISNME=$(cat $INPUT 2>/dev/null | awk -F '<url>' '{print $2}' | awk -F '</url>' '{print $1}' | grep -v "^$" | awk -F '@//' '{print $2}' | cut -d / -f2 | awk '{$1=$1;print}')
    elif [[ -z $DISNME ]]; then
      DISNME="please check manually..."
    fi    
    echo -e "Service name : $DISNME"
    echo -e "\nTry this in sql developer after dercypt.. it might be an old XML or there might be multiple"
    echo -e "\n"
  elif [[ $(echo $INPUT | wc -w) -eq 1 ]]; then
    echo -n "Decrypted Password : $(DECRYPT ${INPUT})"
    echo -e "\n\n"
  else
    echo -e "\nINVALID INPUT PROVIDED....PLEASE VERIFY AND RE-RUN\n"
  fi
elif [ $INPUTDS == "ALLDS" ] && [ $HOST != *prd* ]; then
  #######################################
  #  Below is TO OBTAIN ALL DS details  #
  #  DS-Name  -   USER  -   PASSWORD    #
  #######################################
  if [[ ! -z $(ls -d $TDOMHM/config/jdbc 2>/dev/null) ]]; then
    >$TDOMHM/config/jdbc/decrypted_pswd
    >$TDOMHM/config/jdbc/encrypted_pswd
    >$TDOMHM/config/jdbc/results_wout_pswd
    >$TDOMHM/config/jdbc/DS_OUT.csv
    echo ""
    echo -e "This will take few mins to execute, please hold...."
    echo -e "\tResults will print now also located at\n\t/opt/sw/prd_middleware/MWDev_Test/MWDev_TEAM_CHECKOUT/SOA_JDBC/`hostname`_DS_OUT.csv"
    echo ""
    cd $TDOMHM/config/jdbc
    echo "DataSource,User,Password,JDBC URL" > $TDOMHM/config/jdbc/DS_OUT.csv
    for file in $(ls *.xml); do
      TPASS=$(cat $file | grep -i password)
      if [[ ! -z $TPASS ]]; then
        USR=$(cat $file | grep -A1 user | tail -1 | cut -d '>' -f2 | cut -d '<' -f1)
        #cat $file | grep -i password | cut -d '>' -f2 | cut -d '<' -f1 | awk '{$1=$1;print}') >> $TDOMHM/config/jdbc/encrypted_pswd
        ENCPASS=$(cat $file | grep -i password | cut -d '>' -f2 | cut -d '<' -f1 | awk '{$1=$1;print}')
        DECPASS=$(DECRYPT ${ENCPASS})
        URL=$(cat $file | grep url | cut -d '>' -f2 | cut -d '<' -f1)
        if [[ -z $USR ]]; then USR=unknown; fi
        if [[ -z $URL ]]; then URL=unknown; fi
        if [[ -z $DECPASS ]]; then DECPASS=unknown; fi
        echo "${file},${USR},${DECPASS},${URL}" >> $TDOMHM/config/jdbc/DS_OUT.csv
        #echo "${file},${USR},${URL}" >> $TDOMHM/config/jdbc/results_wout_pswd
        #echo -e "${file}\t${USR}" >> $TDOMHM/config/jdbc/results_wout_pswd
      fi
    done
    ####
    #DECRYPT $TDOMHM/config/jdbc/encrypted_pswd
    ####
    #count=$(cat $TDOMHM/config/jdbc/encrypted_pswd | wc -l)
    #echo "DataSource,User,JDBC URL,Password" >> $TDOMHM/config/jdbc/DS_OUT.csv
    #while [[ $count -ge $new_count ]]; do
    #  OLD=$(cat $TDOMHM/config/jdbc/results_wout_pswd | head -${new_count} | tail -1)
    #  NEW=$(cat $TDOMHM/config/jdbc/decrypted_pswd | head -${new_count} | tail -1)
    #  echo "${OLD},${NEW}" >> $TDOMHM/config/jdbc/DS_OUT.csv
    #  ((++new_count))
    #done
    ####CSV FILE GENERATION####
    cat $TDOMHM/config/jdbc/DS_OUT.csv
    cp $TDOMHM/config/jdbc/DS_OUT.csv /opt/sw/prd_middleware/MWDev_Test/MWDev_TEAM_CHECKOUT/SOA_JDBC/`hostname`_DS_OUT.csv
    echo -e "\nOutput is written in   /opt/sw/prd_middleware/MWDev_Test/MWDev_TEAM_CHECKOUT/SOA_JDBC/`hostname`_DS_OUT.csv\n"
    REMOVE
  else
    echo -e "\n"
    echo -e "No DataSources found...."
    echo -e "\n"
  fi  
else
  echo -e "\n\nINVALID INPUT....\n\n"
fi
