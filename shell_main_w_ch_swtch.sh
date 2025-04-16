#!/usr/bin/zsh

#TO DO TO COMPLETE
#inital/ setup code to be used once
#auto run on start_up
#allow non-superuser packet capture


#parameters / settings
# INTEGERS
loop_position=0
loop_limit=10
capture_duration=5
remove_old_drone=0		#boolean
active_channel=1		#current channel being scanned in channel list

# FILES NAMES & PATHS
capture_decoder_py="packet_processing_script.py"
drone_data_file="drone_array_v4.csv"
drone_data_template="drone_array_v4_blank.csv"
display_data_file="display_data.csv"
operator_data_file="operator_array.csv"
operator_data_template="operator_array_blank.csv"
white_list_file="white_list.csv"
capture_file_name="remoteID_capture.pcapng"
packet_contents_txt="packet_contents.txt"
capture_dest_dir_temp="/home/kali/Desktop/packet_reader_script/"
channel_list=(6 1 11)		# WLAN channels to be scanned. Default channel is the first entry


# INTERFACES
ble_interface="/dev/ttyACM0-4.4"	#BLE interface should be:    /dev/ttyACM0-4.4 confirm by running wireshark and ensuring that the interface names match
wifi_interface="wlan1mon"		#802.11 interface should be:    wlan1mon

# BOOLEAN SETTINGS
single_interface_capture=true	# Should the sniffer be allowed to capture only on BLE when 802.11 is unavailable 
empty_csv_before_use=true
scan_channel_list=false # false uses default channel, true scans through a new channel with each loop


#checks to see if network and BLE adaptors are plugged in
if lsusb | grep -i -q "MediaTek Inc. Wireless_Device";then
	ext_network_mounted=true
	echo "MediaTek Inc. Wireless_Device is ready to be used"
else
	ext_network_mounted=false 
	echo "MediaTek Inc. Wireless_Device not found in device list, make sure it is plugged"
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
sudo iwconfig $wifi_interface channel $channel_list[1]

if $empty_csv_before_use; then
	cat $drone_data_template > $drone_data_file	#replaces contents of the drone_array with an empty template, effectively empything it before each time the script is run
	cat $operator_data_template > $operator_data_file
fi

if $mon_mode_ready; then
	# dual capture while loop captures and processed both BLE and 802.11 packets
	while true; do
		((loop_position++))
		# iterated through channel array when scanning is selected
		if $scan_channel_list; then
			((active_channel++))
			if [[ $active_channel > $#channel_list ]]; then
				active_channel=1
			fi
		fi
		sudo iwconfig $wifi_interface channel $channel_list[$active_channel]
		echo "\n"
		iwlist $wifi_interface channel | grep "Current Frequency" | awk '{$1=$1; print}'
	    	#starts tshark with bluetooth and 802.11 interfaces and saves the capture in the same dir as the packet reader script (/tmp/ by default)
	    	#exports the dissected contents of the pcapng file in dual_capture.txt 
		tshark -i $ble_interface -i $wifi_interface --temp-dir $capture_dest_dir_temp -w $capture_file_name -a duration:$capture_duration		# 
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
