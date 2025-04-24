#!/usr/bin/zsh



#parameters / settings
# INTEGERS
loop_position=0
loop_limit=10
capture_duration=2
remove_old_drone=0		#boolean
active_channel=6		#current channel being scanned in channel list

# FILES NAMES & PATHS
capture_decoder_py="packet_processing_script.py"
drone_data_file="drone_array_v4.csv"
drone_data_template="drone_array_v4_blank.csv"
display_data_file="display_data.csv"
operator_data_file="operator_array.csv"
operator_data_template="operator_array_blank.csv"
current_location="current_location.csv"
qgis_out="drone_location_gui.qgz"
white_list_file="white_list.csv"
capture_file_name="remoteID_capture.pcapng"
packet_contents_txt="packet_contents.txt"
capture_dest_dir_temp="/home/kali/remoteID_reader_loop_script/packet_reader_script/"
channel_list=(1 2 3 4 5 6 7 8 9 10 11 12)		# WLAN channels to be scanned. Default channel is the first entry

cd $capture_dest_dir_temp # ensures that files are saved to the correct directory

# INTERFACES
ble_interface="/dev/ttyACM0-4.4"	#BLE interface should be:    /dev/ttyACM0-4.4 confirm by running wireshark and ensuring that the interface names match
wifi_interface="wlan1mon"		#802.11 interface should be:    wlan1mon or wlan1

# BOOLEAN SETTINGS
single_interface_capture=false	# Should the sniffer be allowed to capture only on BLE when 802.11 is unavailable 
empty_csv_before_use=true
#scan_channel_list=true # false uses default channel, true scans through a new channel with each loop

# asks user if they want to use QGIS as a local map viewer, uses terminal only if they respond with Nn
while true; do
	echo "Do you want to view locations via QGIS? (y/n)"
	read start_qgis
	case "$start_qgis" in
		[Yy]*) start_qgis=true;break;;
		[Nn]*) start_qgis=false;break;;
		*) echo "invalid response, answer y or n";;
	esac
done

# update current_location.csv ot be used by GIS GUI
while true; do
	echo "Do you want to update your current location? (y/n)"
	read new_loc_ans
	case "$new_loc_ans" in
		[Yy]*) use_new_loc=true;break;;
		[Nn]*) use_new_loc=false;break;;
		*) echo "invalid response, answer y or n";;
	esac
done

if $use_new_loc; then
	echo "Enter your current latitude in decimal degree form (xx.xxxxx)"
	read new_lat
	echo "Enter your current longitude in decimal degree form (xx.xxxxx)"
	read new_long
	: > $current_location # empties file before updating current location
	echo "---CURRENT LOCATION---,Latitude,Longitude" >> $current_location
	echo ",$new_lat,$new_long" >> $current_location
fi
clear

# use single default channel or scan through channel_list
while true; do
	echo "Do you want to scan all availible channels outside of the default channel ($channel_list[$active_channel])? (y/n)"
	read scan_ch_ans
	case "$scan_ch_ans" in
		[Yy]*) scan_channel_list=true;break;;
		[Nn]*) scan_channel_list=false;break;;
		*) echo "invalid response, answer y or n";;
	esac
done

# modify capture duration for capture portion of script, longer durations are more likely to capture distant drones, but have a slower update time
echo "Enter the capture duration, or enter 'D' to use default value of " $capture_duration
read cap_dur_ans
case "$cap_dur_ans" in
	[Dd]*) capture_duration=$capture_duration;;
	*) capture_duration=$cap_dur_ans;;
esac

clear

if $start_qgis; then
	qgis $qgis_out & # '&' opens QGIS in the background
	echo "QGIS is starting in the background, this may take a couple seconds...\n"
fi


#checks to see if network and BLE adaptors are plugged in
if lsusb | grep -i -q "MediaTek Inc. Wireless_Device";then
	ext_network_mounted=true
	echo "MediaTek Inc. Wireless_Device is ready to be used"
else
	ext_network_mounted=false 
	echo "MediaTek Inc. Wireless_Device not found in device list, make sure it is plugged in"
fi
if lsusb | grep -i -q "nRF Sniffer";then
	ext_ble_mounted=true
	echo "nRF52840 BLE adaptor is ready to be used"
else	
	ext_ble_mounted=false 
	echo "nRF52840 not found:"
fi

#starts wlan1 in monitor mode, creating the wlan1mon interface for Tshark to use.
sudo airmon-ng start wlan1 # this command kills only processes on wlan1, and allows monitor mode packet capture
iwconfig | grep -i $wifi_interface && mon_mode_ready=true || mon_mode_ready=false
echo "monitor mode ready = " $mon_mode_ready
sudo iwconfig $wifi_interface channel $channel_list[$active_channel]

if $empty_csv_before_use; then
	cat $drone_data_template > $drone_data_file	#replaces contents of the drone_array with an empty template, effectively empything it before each time the script is run
	cat $operator_data_template > $operator_data_file
fi

if $mon_mode_ready; then
	# dual capture while loop captures and processed both BLE and 802.11 packets
	while true; do
		echo "active channel: "
		echo $active_channel
		echo "\nchannel list length: "
		echo ${#channel_list[@]}
				
		((loop_position++))
		# iterated through channel array when scanning is selected
		if $scan_channel_list; then
			
			if [ $active_channel -eq ${#channel_list[@]} ]; then
				active_channel=1
			else
				((active_channel++))
			fi
		fi
		sudo iwconfig $wifi_interface channel $channel_list[$active_channel]
		echo "\n"
		iwlist $wifi_interface channel | grep "Current Frequency" | awk '{$1=$1; print}'
	    	#starts tshark with bluetooth and 802.11 interfaces and saves the capture in the same dir as the packet reader script (/tmp/ by default)
	    	#exports the dissected contents of the pcapng file in dual_capture.txt 
		tshark -i $wifi_interface --temp-dir $capture_dest_dir_temp -w $capture_file_name -a duration:$capture_duration		# -i $ble_interface 
		tshark -QPVr $capture_file_name > $packet_contents_txt
		#clear
		#-i denotes the interface used
		#--temp-dir sets the temporary director used to save pcapng files
		#-w sets the name of the written file
	    	#-P includes packet line
	    	#-V includes packet contents as captured and dissected
	    	#-2 passed over each instance twice to ensure all data is collected
	    	#-r reads the PCAPNG file
	    	#-Q option for quiet operation
	    	#-a duration:<seconds> autostops after a certain number of seconds (may be needed)
		python3 $capture_decoder_py $loop_position $loop_limit $drone_data_file $operator_data_file $white_list_file $packet_contents_txt $display_data_file $remove_old_drone
		clear
		column -s, -t <$display_data_file & #prints CSV as column oriented array
	done
else
	while $single_interface_capture; do
		echo "BLE only capture taking place"
		((loop_position++))
		tshark -i $ble_interface --temp-dir $capture_dest_dir_temp -w $capture_file_name -a duration:$capture_duration
		tshark -QPVr $capture_file_name > $packet_contents_txt
		python3 $capture_decoder_py $loop_position $loop_limit $drone_data_file $operator_data_file $white_list_file $packet_contents_txt $display_data_file $remove_old_drone
		clear
		column -s, -t <$display_data_file & #prints CSV as column oriented array

	done
	if [[ $single_interface_capture != true ]]; then
		echo "Single Interface Capture not allowed in config, quitting loop"
	fi
fi
