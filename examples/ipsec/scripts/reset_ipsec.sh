#!/usr/sbin/setkey -f

# NOTE: Do not use this file if you use racoon with racoon-tool
# utility. racoon-tool will setup SAs and SPDs automatically using
# /etc/racoon/racoon-tool.conf configuration.
# 

# Configuration for aaaa::1

# Flush the SAD and SPD
flush;
spdflush;
