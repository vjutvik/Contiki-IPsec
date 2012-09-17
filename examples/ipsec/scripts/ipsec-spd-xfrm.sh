# Set the SPD via the XFRM interface

# Flush the SPD
ip xfrm policy deleteall dir in
ip xfrm policy deleteall dir out
ip xfrm policy deleteall dir fwd

ip xfrm policy add dir out src aaaa::1 dst aaaa::302:304:506:708 proto udp tmpl src aaaa::1 dst aaaa::302:304:506:708 proto esp mode transport reqid 3 level required

# mode transport reqid 3 level required