#!/usr/bin/zsh

# WARNING THIS IS THE EXPERIMENTAL RELEASE
cd /home/kali/Desktop/packet_reader_script/ # ensures that files are saved to the correct directory


#parameters / settings
# INTEGERS
loop_position=0
loop_limit=10
capture_duration=5
remove_old_drone=0		#boolean

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

# INTERFACES
ble_interface="/dev/ttyACM0-4.2"	#BLE interface should be:    /dev/ttyACM0-4.2
wifi_interface="wlan1"		#802.11 interface should be:    wlan1mon

# BOOLEAN SETTINGS
single_interface_capture=false	# Should the sniffer be allowed to capture only on BLE when 802.11 is unavailable 
empty_csv_before_use=true
remove_old_drones=false		#IMPLEMNENT THIS OPTION


#checks to see if network and BLE adaptors are plugged in
if lsusb | grep -i -q "RT5572";then
	ext_network_mounted=true
	echo "RT5572 Network adaptor is ready to be used"
else
	ext_network_mounted=false 
	echo "RT5572 not found in device list, make sure it is plugged, you may have to press the reset button on the side"
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
iwconfig | grep -i "wlan1" && mon_mode_ready=true || mon_mode_ready=false
echo "monitor mode ready = " $mon_mode_ready
sudo iwconfig wlan1 channel 6

if $empty_csv_before_use; then
	cat $drone_data_template > $drone_data_file	#replaces contents of the drone_array with an empty template, effectively empything it before each time the script is run
	cat $operator_data_template > $operator_data_file
fi

if $mon_mode_ready; then
	# dual capture while loop captures and processed both BLE and 802.11 packets
	while true; do
		((loop_position++))
	    	#starts tshark with bluetooth and 802.11 interfaces and saves the capture in the same dir as the packet reader script (/tmp/ by default)
	    	#exports the dissected contents of the pcapng file in dual_capture.txt 
		tshark -i $wifi_interface --temp-dir $capture_dest_dir_temp -w $capture_file_name -a duration:$capture_duration		#-i $ble_interface 
		tshark -QPVr $capture_file_name > $packet_contents_txt
		clear
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
