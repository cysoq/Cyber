# Wireshark Essentials 
Wireshark (previously knwon as Ethereal) is the de-facto packet analysis tool 
+ Wireshark can dissect a large number of common protocols, including Ethernet, IP, TCP, UDP, and 802.11, and more esoteric ones including ATM and EtherCAT
+ It handles live capture on different mediums, can open or save data in a number of capture formats, and allows us to do analysis and data graphing
+ The display and capture filters allow us to narrow down the amount of data displayed and received, which often comes in handy

Wireshark is available on a wide variety of operating systems as a GUI and as a command line tool called _TShark_
+ Wireshark includes other command line tools including _dumpcap_, which handles packet capture but doesn't do any dissection
+ And _SSHdump_, which simplifies remote packet capture via SSH

## Getting Started 
Will explore the Wireshark GUI and discuss various features and settings
+ Wireshark will capture Ethernet packets by default, even when we are using a wireless interface
+ In order to collect only raw wireless frames, the Wi-Fi adapter must be put in *monitor* mode prior to launching Wireshark, will do the following to do so:
``` Shell
sudo ip link set wlan0 down
sudo iwconfig wlan0 mode monitor
sudo ip link set wlan0 up
```

### Welcome Screen 
When launched, Wireshark presents a screen like the one below:
![[Pasted image 20230904203835.png]]
+ This screen displays the _Display Filter_, recently opened files, the _Capture Filter_ setup, the list of interfaces, the traffic sparklines, and other relevant information
+ The sparklines show network activity on each of the interfaces and they go up and down depending on the amount of traffic
+ Wireshark refreshes the interfaces list as they are removed or added, but it doesn't show ones that are down

To the right of the capture filter textbox there is a dropdown that displays the different types of interfaces available
+ Checking and unchecking will show or hide certain interfaces based on their type. We will select _Wireless_ in order to focus on wireless only
![[Pasted image 20230904203936.png]]

If there are no wireless interfaces, the _Wireless_ option will not be present
+ We might see other categories such as _USB_ for USB devices, _Bluetooth_ for Bluetooth devices, and _Virtual_ for interfaces related to virtualization software

After closing the interface type selector, the list of interfaces below the capture filter textbox will update
+ There are two ways to start the capture:
	+ Can either double-click on the interface
	+ Can select the interface and then click on the shark fin right below the _File_ menu;
![[Pasted image 20230904204100.png]]

### Packet Display 
Once we start the capture, packets begin appearing in our display. We can see the Wireshark window arranged into three frames
- _Packet List_ contains a list of all captured packets with details in customizable columns containing information such as source, destination, protocol, etc.
- _Packet Details_ contains dissected details of the currently selected packet.
- _Packet Bytes_ contains the hexadecimal representation of the actual bytes of the packet. When an item is selected in _Packet Details_, the corresponding bytes are highlighted in this field
![[Pasted image 20230904204205.png]]

In the upper left of our display, the toolbar now has the _Start Capture_ button greyed out
+ The red _Stop Capture_ button and the green _Restart Capture_ button are now active

The packet list layout can be rearranged in various ways:
+ Will select `Edit > Preferences > Appearance > Layout` to choose another arrangement
![[Pasted image 20230904204301.png]]

We can change the layout, order, or disable panes if desired
+ We will select the second layout, which places the _Packet Details_ and _Packet Bytes_ side by side
+ This will be helpful when examining the content of the frames:
![[Pasted image 20230904204402.png]]

### Wireless Toolbar
The Wireshark wireless toolbar will allow us to change channels manually, as well as set the channel width 
+ This toolbar is disabled by default but can be enabled by checking `View > Wireless Toolbar`: 
![[Pasted image 20230904205023.png]]

Once selected, the toolbar gets added below the display filter toolbar:
![[Pasted image 20230904205554.png]]
+ The _802.11 Preferences_ button, at the far right of the toolbar, is a shortcut to the 802.11 protocol preferences, which contains various 802.11 settings

Wireshark doesn't _channel hop_
+ It will stay on whatever channel the wireless adapter is currently on
+ To quickly scan all channels on 2.4GHz, we can run the following shell script in the background in a terminal:
``` Bash
#!/bin/bash

# Will need to pass in the interface as the first arg, will need to run with sudo
for channel in 1 6 11 2 7 10 3 8 4 9 5
do
  iw dev $1 set channel ${channel}
  sleep 1
done
```

Could use _airodump-ng_ to do channel hopping
+ Airodump-ng is meant to be a full-blown tool to capture wireless frames and has a handy default behavior of channel hopping without saving any data
+ Running `sudo airodump-ng wlan0mon` will achieve a result similar to the shell script above

### Saving and Exporting Packets 
After doing a packet capture, we can save the whole contents of the packet list into a file use `File > Save or File > Save As_=`
+ The most common format is *PCAP* 
+ The capture file may be compressed with _GZIP_ to save disk space
+ Two of the less common formats, such as _PCAPng_ and _nanosecond PCAP_ can both be accurate to the nanosecond 
+ They are a thousand times more precise than PCAP, which uses microsecond precision
+ Having said this, the regular PCAP format works just fine for most scenarios and it also has excellent compatibility with other tools handling packet captures

Wireshark offers the ability to filter what is saved to a file. We can edit this using the _File_ > _Export Specified Packets..._ option
![[Pasted image 20230904210649.png]]

This is similar to _Save_ and _Save as..._ but with a number of options shown in the lower left box
+ Selecting _Displayed_ saves only those packets shown as a result of a currently applied filter. _Captured_ saves all the packets

We can further refine the choice of packets using radio buttons.
- _All packets_ is the default option
- _Selected packets only_ saves one or multiple packets selected with the B key.
- _Marked packets only_ includes packets marked in the packet list by right-clicking and selecting _Mark/Unmark Packet_.
- _First to last marked_ saves all packets between the first and last marked packets.
- _Range_ includes packets that have packet numbers landing in a particular range (for example, packets 5-10).
- _Remove ignored packets_ will exclude ignored packets. To ignore a packet, we right click on it and select _Ignore/Unignore Packet_.

## Wireshark Filters
Packet capture consists of collecting a lot of data
+ Filters allow us to cut down on the amount of data we have to wade through so that we deal with only what is necessary or relevant
+ Wireshark uses two types of filters in order to limit what needs to be analyzed, _display filters_, which limit the packets that are displayed, and _capture filters_, which limit the amount of data captured

### Wireshark Display Filters 
Display Filters affect which packets are visible in Wireshark's packet list 
+ These filters impact what is displayed, and can/will capture additional packets that are not visible 
+ Display filters are applied and edited in the _Filter_ toolbar located between the _Main_ toolbar and the packet list:
![[Pasted image 20230905133444.png]]

#### Display Filter Expression 
The best way to understand the syntax of Wireshark display filters is to create one with the Display Filter Expression screen
+ Will select `Analyze > Display Filter Expression...` to open the screen with all the available filters:
![[Pasted image 20230905133712.png]]

Each display filter has a _field name_ and _relation_, as well as a _value_, if applicable
+ The text box highlighted in green is where the filter expression is displayed

Can think of the _field_ as an object with one or more items
+ The field can be built using dot-notation
	+ This is similar to what we would see in object-oriented programming languages
+ The _Field Name_ displays the object and a short description
+ Hovering the mouse in the _Relation_ window displays a pop-up that provides more details:
![[Pasted image 20230905133905.png]]
A display filter expression's _relation_ can be one of the following: `is present`, `==`, `!=`, `<`, `>`, `>=`, `<=`, `contains`, `matches`, `in` 
+ Depending on the field selected, not all relations will be available

The _Search_ field, located below the _Field Name_ list, is useful when we can't remember a specific filter
+ It will narrow down the list of field names as we type, and it shows matching results from both the names and their descriptions
![[Pasted image 20230905134151.png]]

The _Predefined Values_ window contains a number of options that relate to different byte values in certain packet fields
+ For example, _wlan.fc.type_ can have four different values: 0, 1, 2, and 3
+ These relate to _Management_, _Control_, _Data_, and _Extension_ frames, respectively
+ Our chosen `wlan.fc.type == 2` filter in Figure 13 has "byte value 2", which filters for _data frames_

Clicking _OK_ updates the contents of the display filter toolbar with our selected filter and the resultant packets as shown below:
![[Pasted image 20230905134350.png]]

#### Packet Details
Can also build filters based on items from a selected packet
+ Will illustrate this by creating a data frame packet filter
+ We will start by selecting a data packet from the packet list:
![[Pasted image 20230905134438.png]]
+ In the packet's detail window, let's expand the _IEEE 802.11 Data, Flags_ field and the _Frame Control Field_ and then right click the _Type: Data frame (2)_ element
+ Finally, we'll select _Apply as Filter_ (selecting _Analyze_ in the Main toolbar also displays these options);
![[Pasted image 20230905134719.png]]

Now we have a number of options to choose from.
- _Selected_ clears the display filter bar of any existing queries and generates a new query to search for this specific value. For example, wlan.fc.type with a value of "2" generates "wlan.fc.type == 2" in the display filter bar.
- _... and Selected_ appends to any existing query by using an _AND_ (&&) condition. Taking the query we created above and adding a wlan.fc.subtype value of "0" generates "(wlan.fc.type == 2) && (wlan.fc.subtype== 0)" in the display filter bar.
- _... or Selected_ does the same as the above filter but instead of using an AND, it uses an _OR_ (||) condition.

All the choices containing "Not" negate their equivalent in the positive form. For example, if we have `wlan.fc.type == 2` as an existing filter and use _... and not Selected_ with `wlan.fc.subtype` and value of "0", the filter becomes `(wlan.fc.type == 2) && !(wlan.fc.subtype == 0)`

Note that _Apply as filter_ builds and applies the filter immediately
+ While _Prepare a filter_ only updates the contents of the display filter bar and doesn't apply the filter until we click _Apply display filter_ at the end of the display filter textbox
+ _Prepare a filter_ is useful when we want to build a complex filter that will require multiple steps
+ As the list of collected packets gets longer, it can take time to process each new subfilter that gets applied
+ It might be easier to wait to apply the filter until after we have finished writing the complete query

#### Display Filter Toolbar
We can also create and access display filters directly in the Display Filter toolbar
+ On the left, a blue ribbon icon will bring us to bookmarked filters:
![[Pasted image 20230905140010.png]]
+ To the right of the filter bar there is an arrow and a dropdown icon
+ The arrow will apply the filter, while the dropdown will show the most recent display filters:
![[Pasted image 20230905140032.png]]

When creating a filter, Wireshark's autocompletion displays valid filters as the expression is typed:
![[Pasted image 20230905140049.png]]

The toolbar provides filtering hints with colored backgrounds
+ A valid filter is displayed with a green background
+ An invalid filter is indicated by a red background
+ For example, the `wlan.fc.type = 1` filter is syntactically incorrect because it uses only a single `=`, so it appears with a red background

A yellow background indicates a possibly questionable filter
+ Yellow doesn't always mean the filter is incorrect
+ In most cases, it will be correct as most filters reference a single field
+ For example, it is better practice to do `!(wlan.fc.type == 1)` instead of `wlan.fc.type != 1` so a it can show in yellow for that reason 

Display Filters Bookmarks
+ When doing a lot of packet filtering, we may want to reuse filters
+ This is where the bookmarks come in handy, they allow us to save display filters for later use
+ The bookmark button is located on the left of the Display Filter toolbar
![[Pasted image 20230905140336.png]]

Clicking on the bookmark reveals a default set of display filters and any additional saved filters:
![[Pasted image 20230905140348.png]]

When a valid filter is in the Display Filter toolbar, _Save this filter_ is clickable in the bookmark dropdown menu
+ Saving the filter opens the _Display Filters_ screen and the new filter is displayed at the bottom of the list
+ Selecting _OK_ saves the filter in the bookmark list
![[Pasted image 20230905140436.png]]

We can create and save a new filter by either selecting `Manage Display Filters` from the bookmarks dropdown menu or via `Analyze > Display Filters...`
+ Both of these options open the Display Filters screen

We can edit an existing filter by selecting it and applying valid changes
+ Valid changes are indicated by the green (or yellow) background in the Filter field
+ Filters from the list can be deleted with the minus ("-") button or duplicated with the _Copy_ button

#### Display Filter Buttons 
We can add a shortcut to the Display Filter toolbar for frequently used filters by selecting the plus `+` icon located on the very right of the toolbar
+ This opens a Create Shortcut Button panel:
![[Pasted image 20230905143332.png]]

We will enter the name of the shortcut in the _Label_ field and enter the filter in the _Filter_ field
+ The _Comment_ field is for a description that appears when hovering the mouse over the shortcut button:
![[Pasted image 20230905143717.png]]

Selecting _OK_ creates our _Data_ button to the right on the Display Filter toolbar
+ Hovering the mouse on the button displays the filter's comment:
![[Pasted image 20230905143811.png]]

Clicking on our new button sets the content of the filter toolbar to `wlan.fc.type == 2`
+ Right-clicking the button gives us options to edit, disable, or remove the button
![[Pasted image 20230905143839.png]]

Editing a button will bring back the creation panel below the Display Filter bar
+ This time, the creation panel will be prefilled with the button's existing settings
+ Filter buttons can also be created, deleted, or edited via `Edit > Preferences...`, and selecting `Filter Buttons` in the left panel

### Wireshark Capture Filters 
TODO, LEFT OFF HERE 