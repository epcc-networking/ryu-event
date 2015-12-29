# Usage: 
===
ryu-manager(or $ryupath/bin/app-manager) --observe-links forwarding.py for elephant detection, and flow scheduling
import event_message_ofp10.py to use events of OpenEvent in OpenFlow 1.0
import event_message_ofp13.py to use events of OpenEvent in OpenFlow 1.3
# description of files:
===
event_message_common.py: specify common things in messages in OpenEvent
event_message_ofp10.py: encode and decode messages in OpenEvent in OpenFlow 1.0
event_message_ofp13.py: encode and decode messages in OpenEvent in OpenFlow 1.3
common.py: used by the following applications, holds information of switches and links between switches
forwarding.py: topology discovery , forwarding flows, and link utiliztion monitoring
elephant_detect_event.py: detection and maintain of elephant flows
scheduling.py: scheduling of elephant flows in fat tree network

