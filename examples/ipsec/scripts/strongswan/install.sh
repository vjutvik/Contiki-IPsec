#if [ ${uname} = "Linux" ]; then
  cp scripts/strongswan/ipsec.conf scripts/strongswan/strongswan.conf scripts/strongswan/ipsec.secrets /etc/
  ipsec restart
# else
#   # Darwin assumed
#   cp scripts/strongswan/ipsec.conf scripts/strongswan/strongswan.conf scripts/strongswan/ipsec.secrets /usr/local/etc/
#   /usr/local/libexec/ipsec/charon
# fi

