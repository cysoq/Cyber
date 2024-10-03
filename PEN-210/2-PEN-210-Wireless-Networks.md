# Wireless Networks 
There are many different ways in which a wireless network might be designed
+ As our attack vectors, methods, and even the tools we use are dictated by the target network configuration and the security protocols in use, it's a good idea to have a working knowledge of the full variety of different arrangements

## Overview 
Here are some of the architectures and modes we will review along with a brief explanation of each:
- _Infrastructure_ is the term we'll use to describe the organization and relationships between access points (APs) and clients. A network architecture may have a very basic infrastructure, or it may include a number of the other concepts discussed in this module.
- _Wireless Distribution System_ is a way to connect multiple APs without Ethernet cables between them in order to create a single network. Different APs may have different roles in the network.
- _Ad-Hoc Networks_ are a type of network in which all devices are equal. In an Ad-Hoc network, the initiating device takes care of AP duties such as beaconing and authentication.
- _Mesh Networks_ are a type of network where all APs are equal, and don't have defined roles. Mesh networks are most often used to extend a network's reach in areas where running cable is difficult or impossible. There are a variety of proprietary technologies for mesh networks, but they are not compatible with each other.
- _Wi-Fi Direct_ is also known as Wi-Fi Peer-to-Peer (P2P). It allows temporary connections between two or more devices to share items such as files, a display, or other services.
- _Monitor Mode_ is not an architecture, per se, but a mode used by wireless cards that will help us capture Wi-Fi frames and inject packets during a penetration test.

In _all_ architectures (except in monitor mode), a Service Set Identifier (**SSID**) is required for network verification
+ In mesh, Wi-Fi P2P, and infrastructure architectures, the *AP sets the SSID*, whereas in Ad-Hoc mode, the station creating the network sets it

## Infrastructure 
Basic infrastructure will have the following: 
+ There is at least one **AP**
+ There is at least one station (**STA**) (edge device like laptop or phone)
	+ This and the AP form a Basic Service Set (**BSS**)
+ The AP is usually connected to a wired network, called the *Distribution System* (**DS**) (Network device like a router)

A simple example of this would be a station (**STA**), such as a laptop or smartphone, connected to a wireless access point (**AP**), which is connected by an ethernet cable to a wired router (**DS**).
+ This might be the sort of setup one might find in a home or very small office
+ On Linux-type operating systems, acting as a station is usually called _Managed_ mode and acting as an AP is usually called _Master_ mode

When a set of two or more wireless APs are connected to the same wired network, we call this an *Extended Service Set* (**ESS**)
+ Each additional AP defines a single logical network segment
+ Set the DS, BSS, and ESS relationships: 
![[Screenshot 2023-08-04 at 3.54.33 PM.png]]

To expand on our previous example of the small office network, we would take an additional network cable connected to the original access point (which has DS capabilities). We would run that cable to an area in the office that the first AP signal cannot reach. At that point, we would hook up a new wireless router. Laptops in this part of the office could use the new router as an AP, while a laptop closer to the old router would use the other AP.

## Wireless Distribution Systems 
Wireless Distribution Systems (**WDS**)
+ APs are attached to a Distribution System (DS), a wired network
+ In cases where the router and AP functions are integrated, the DS would be anything other than the wireless network itself
+ WDS, on the other hand, is just what it sounds like. It is a *DS going over Wi-Fi instead of a cable*

WDS has two connectivity modes:
- _Wireless Bridging_: Only allows WDS APs to communicate with each other.
- _Wireless Repeating_: Allows both stations and APs to communicate with each other.

The figure below shows an example of a WDS setup:
![[Screenshot 2023-08-04 at 4.15.18 PM.png]]

Let's consider another very basic example of a network with WDS. We'll use the example of our small office again. Let's say that the storage room in the back of the building has a computer that is too far away from the wireless router in the front of the building. Our business owner might install an additional access point near the storage room without running ethernet cable to it. The computer in the storage room communicates with the second AP, which carries the signal to the first AP in the front of the building, which is connected to the wired DS.

A WDS typically uses the same channel as the existing access point for back-haul. This channel sharing has an impact on high-traffic networks as the available data rates can be cut in half. In low-traffic networks, this likely won't be an issue.

## Ad-Hoc Networks 
An _Ad-Hoc_ network may not be something we see often, but we should be aware of them
+ An Ad-Hoc network, also known as an Independent Basic Service Set (**IBSS**), consists of at least two stations communicating without an AP
+ In an Ad-Hoc network, one of the participating stations takes on some of the responsibilities of an AP, such as beaconing and authentication of new clients joining the network
+ The station taking on the responsibilities of the AP does not relay packets to other nodes like an AP does
+ See Ad-Hoc network configuration:
![[Screenshot 2023-08-04 at 4.18.33 PM.png]]

*Neither WDS nor Ad-Hoc* (with a routing protocol) are ideal due to both the complexity of the setup and bugs in the implementations of the standard by the various vendors. The more repeaters that are added, the greater the complexity in setting up, as well as in managing and routing packets efficiently. In Ad-Hoc, bugs lead to random disconnection of certain nodes on the network. WDS is often limited to WEP or unencrypted networks, and WPA is tricky to get working.

### Ad-Hoc Demo
_Ad-Hoc Demo_ is a deviation from a standard Ad-Hoc or IBSS mode
+ This mode is also called _Pseudo-IBSS_ because it's a pre-standard, pre-IBSS mode with just data
+ There are no management frames whatsoever (no beaconing to advertise the network, no association), and the BSSID is all zeros

There are a number of pros and cons to Ad-Hoc Demo mode
+ It could be seen as a raw or bare Ad-Hoc mode. As such, we have to set the rate manually on all the wireless cards
+ The lack of management frames and collision avoidance mechanisms allow for a slightly higher throughput, but it requires a clear channel or strong signal

## Mesh Networks 
The coverage for a typical Wi-Fi network is limited by the APs
+ Additional APs can be added to increase coverage, but they need to be close to a network socket
+ This can be a problem in large indoor environments such as warehouses, outdoor areas like campuses, or historically protected monuments and buildings where we can't drill holes to run network cables from one AP to the next

Mesh networks can be a good solution in these cases
+ They can be configured using existing equipment and technologies
+ Additional access points are added to the infrastructure to determine the best "signal path" for a station on the network
+ In this case, additional APs act as both a client (to the AP they are repeating) and also as an AP to further repeat the signal
+ 802.11s is an amendment of 802.11 to standardize mesh networking

One could create a mesh network by using Ad-Hoc mode
+ In this case, the setup is fairly complex and requires additional software to handle packet routing across nodes using protocols such as AODV, BATMAN, or OSLR
+ On the other hand, 802.11s was designed for networks up to 32 nodes, with a default routing protocol called Hybrid Wireless Mesh Protocol (**HWMP**)
+ A variety of vendors provide mesh-type solutions, but because their protocols are proprietary, they are neither interoperable nor compatible with 802.11s

In addition to the similarities with infrastructure networks, 802.11s adds the following device classes:
- _Mesh Point (MP)_: Devices that establish a link between mesh devices. These can be either Mesh Portals, Mesh APs, or even other Mesh Points.
- _Mesh AP (MAP)_: Devices that have the functionality of a Mesh Point and an Access Point.
- _Mesh Portal (MPP)_: Devices that provide a link between the wired network and the wireless network.

See the Mesh network diagram:
![[Screenshot 2023-08-04 at 4.24.14 PM.png]]
+ The red links represent the mesh radio links and the blue links represent the wireless connections with stations
	+ For example, the tablet with the stylus may communicate with the nearest MAP, but depending on a number of factors, those packets may take one of several routes to the DS

In addition to the functionality we've described here, we need to consider that devices in wireless networks sometimes move or disappear, so the path a packet takes will not be always the same
+ The path is dynamically generated by software that takes various changing parameters into account such as signal quality, noise, rate, response time, or distance between nodes

Since Mesh is peer-to-peer (P2P), mesh devices have to handle neighbor discovery, connecting to peers, and security between each other
+ After discovering neighbor MAPs, they start the peering
+ The connection is maintained as long as both devices are in range and continue to respond to frames

There are two peering modes available:
- _Mesh Peering Management (MPM)_: Unsecure peering
	- MPM is unencrypted and rogue stations may hijack connections
- _Authenticated Mesh Peering Exchange (AMPE)_: Secure peering
	- AMPE, the encrypted protocol, uses either Simultaneous Authentication of Equals (SAE) or 802.1X to exchange encryption keys. SAE is a password-based authentication mechanism whereas 802.1X uses an authentication server. Although 802.1X is stronger than SAE, it uses an authentication server and, depending on the status of the 802.1X network, there may not be a path to the authentication server, or the path may become broken.

## Wi-Fi Direct 
Wi-Fi Direct allows direct, single-hop communications between devices and is most commonly used for printing, file sharing, and displaying pictures or videos
+ The connection is usually one-to-one, but devices can also form groups

To use our running example of our small office, it may be common to have a printer connected to the Wi-Fi network. This would be considered multi-hop, since the data goes from the laptop that wants to print, to the AP, and finally on to the printer. Wi-Fi Direct, in contrast, allows the laptop to communicate directly with the printer, even if, for example, the laptop is not connected to the same infrastructure as the printer

Wi-Fi Direct is also called Wi-Fi P2P. It is not an 802.11 standard or an amendment, but a technical specification from the Wi-Fi alliance

Devices offering a service act as a software access point with WPS-style connections using WPA2 encryption
+ It must also allow service discovery
+ The features supported by the software access point are more or less complex depending on the services offered and may replace Bluetooth in some situations

Some Wi-Fi Direct application examples are:
- Photo printing kiosks
- Picture frames to display photo albums
- Remote displays such as Miracast
- File sharing between devices
- Playing games
- Internet sharing (tethering)

## Monitor Mode
Monitor mode is not a wireless mode or architecture scheme, but rather the state of a wireless device that allows it to monitor all Wi-Fi signals within its range

Let’s imagine a scenario in which we are in a parking lot outside our penetration testing target. 
+ There are a handful of laptops connected to the target’s Wi-Fi network. 
+ If we put our Wi-Fi card in monitor mode, we’ll see **much more than just ourselves**, the AP, and all the other clients connected to the same AP. 
+ We will also see **traffic from any other network within range**, such as nearby businesses, residences, and mobile Wi-Fi hot spots.

Monitor mode is essential for wireless penetration testing as it enables the capture of raw 802.11 frames and allows packet injection. The majority of the tools used to test Wi-Fi networks require our wireless interface to be in monitor mode