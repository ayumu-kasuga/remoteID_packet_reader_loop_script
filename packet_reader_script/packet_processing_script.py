"""
packet_processing_script.py
Captstone Team 10 2024-2025

Opens a CSV file which contains a cache of drone data. 

Reads PCAP files exported in wireshark as test files by looping through the entie files until
it reachs a line that contains a droneID, if this is an old droneID it filters through the rest 
of the data contained in the packets and inserts them in the appropiate row, if the droneID is
new is increments and adds the drone in a blank column

arguements = loop position, max loop, drone_path, white_list_path, operator_array_path, pcap_file_txt
"""

# ADD TIME OUT SECTION USING FIRST TWO ARGUEMENTS


import csv
import numpy as np  #numpy not recognized in VC code but funcitonal, use where instead of index
import sys         #allows the script to be run with CLI arguements
import traceback
from array import *

# arguements to be used to determine loop limits and file names
loop_position = int(sys.argv[1])             # current position in while loop 
loop_limit = int(sys.argv[2])                # timeout limit, drones not detected for x cycles are removed from list
drone_data_file_path = sys.argv[3] 
operator_data_file_path = sys.argv[4]
white_list_file_path = sys.argv[5]
packet_content_file_path = sys.argv[6]
display_data_file_path = sys.argv[7]
remove_old_drones = int(sys.argv[8])


with open(drone_data_file_path, mode='r', newline='') as drone_data_file:
    drone_data_temp = list(csv.reader(drone_data_file))
with open(white_list_file_path, mode='r', newline='') as white_list_file:
    white_list_temp = list(csv.reader(white_list_file))
with open(operator_data_file_path, mode='r', newline='') as operator_data_file:
    operator_data_temp = list(csv.reader(operator_data_file))
pcap_file = open(packet_content_file_path, 'r').readlines()


drone_data = np.array(drone_data_temp)
operator_data = np.array(operator_data_temp)
white_list = np.array(white_list_temp)
new_drone = np.empty([1,len(drone_data_temp[0])], dtype='U64') #to be used later when appending drone data rows
new_operator = np.empty([1,len(operator_data_temp[0])], dtype='U64')


# vars
loop_in_ua_packet = 0
contains_airborne = 0
contains_crc_error = 0
old_drone_num = loop_position - loop_limit 
#if a drone is detected its loop_position will be updated, if it is no longer detected the loop_position will
# be deprecated, once the position is less than some current position - loop_limit, it will be too old and removed


#for loop runs through text file
for line in pcap_file:
    #print(str(loop_in_ua_packet))
    if "Open Drone ID - Message Pack" in line and loop_in_ua_packet == 0 and contains_crc_error == 0:       # or use "Broadcast" and "OPENDRONEID"
        loop_in_ua_packet = 1
    elif "CRC: Error" in line: #Cyclical Redundancy Check
        contains_crc_error = 1
        print("CRC Error Detected, Packet Ignored")
    elif "Airborne (2)" and "Operational Status:" in line and loop_in_ua_packet == 1:
        contains_airborne = 1
    elif "frame" and "on interface" in line and loop_in_ua_packet == 1:       # beginning of next packet, effectivly end of current packet "Timestamp Accuracy"
        operator_id_str = "Not Sent"
        loop_in_ua_packet = 0
        contains_airborne = 0
        contains_crc_error = 0 #resets CRC error status to 0 after the whole packet is read

#ARRAY FILLING ALGORITHM____________________________________________________________________________
        if drone_id_type_int == 1: #(Serial number transmitted) ADD "IF PACKET CONTAINS ERROR" as no clean packets contain errors
            serial_number = drone_id_str #sets detected ID as serial number
            if serial_number in white_list[1,:]:      #checks whilelist for serial number in row 1
                white_list_entry_position = int(np.where(white_list == serial_number)[1]) # sets value to column in list
                affiliation = white_list[0,white_list_entry_position]
                drone_name = white_list[2,white_list_entry_position]
                if affiliation == "":               #serial number inlist without affiliation
                    affiliation = "unspecified"
                elif drone_name == "":
                    drone_name = "unspecified"
            else:
                affiliation = "unknown"             # no serial number in list
                drone_name = "unknown"

            #updates existing drone entry if it exists in drone_array.csv and appends it as a new row otherwise
            if serial_number in drone_data[:,1]:      #check if serial number exists in array
                serial_number_position = int(np.where(drone_data == serial_number)[0]) 
                #finds position of serial number in array and overwrites existing entry at location
                try:
                    drone_data[serial_number_position,1] = serial_number
                    drone_data[serial_number_position,3] = ua_type_str
                    drone_data[serial_number_position,4] = operator_id_str
                    drone_data[serial_number_position,5] = affiliation
                    drone_data[serial_number_position,6] = operational_status_str
                    drone_data[serial_number_position,7] = speed_multiplier_str
                    drone_data[serial_number_position,8] = direction
                    drone_data[serial_number_position,9] = speed
                    drone_data[serial_number_position,10] = vert_speed
                    drone_data[serial_number_position,11] = latitude
                    drone_data[serial_number_position,12] = longitude
                    drone_data[serial_number_position,13] = pressure_alt
                    drone_data[serial_number_position,14] = geo_alt
                    drone_data[serial_number_position,15] = height_agl
                    drone_data[serial_number_position,16] = drone_name  # from white list
                    drone_data[serial_number_position,17] = loop_position

                except:
                    print("ALERT: Error updating UA in list")
            else:
                # appends array by adding a new row 'new_drone' and adding it to the bottom of the list
                try:
                    new_drone[0,1] = serial_number
                    new_drone[0,3] = ua_type_str
                    new_drone[0,4] = operator_id_str
                    new_drone[0,5] = affiliation
                    new_drone[0,6] = operational_status_str
                    new_drone[0,7] = speed_multiplier_str
                    new_drone[0,8] = direction
                    new_drone[0,9] = speed
                    new_drone[0,10] = vert_speed
                    new_drone[0,11] = latitude
                    new_drone[0,12] = longitude
                    new_drone[0,13] = pressure_alt
                    new_drone[0,14] = geo_alt
                    new_drone[0,15] = height_agl
                    new_drone[0,16] = drone_name                    # Name from white list
                    new_drone[0,17] = loop_position
                    drone_data = np.vstack([drone_data, new_drone]) #add a new row containing new drone data

                except:
                    print("ALERT: error appending UA to list")
                    traceback.print_exc()

            if serial_number in operator_data[:,1]:      #check if serial number exists in array
                serial_number_position = int(np.where(operator_data == serial_number)[0]) 
                try:
                    operator_data[serial_number_position,1] = serial_number
                    operator_data[serial_number_position,3] = operator_id_str
                    operator_data[serial_number_position,4] = affiliation
                    operator_data[serial_number_position,5] = op_latitude
                    operator_data[serial_number_position,6] = op_longitude
                    operator_data[serial_number_position,7] = op_geo_alt
                except:
                    print("ALERT: Error updating operator in list")
            else:
                try:
                    new_operator[0,1] = serial_number
                    new_operator[0,3] = operator_id_str
                    new_operator[0,4] = affiliation
                    new_operator[0,5] = op_latitude
                    new_operator[0,6] = op_longitude
                    new_operator[0,7] = op_geo_alt
                    operator_data = np.vstack([operator_data, new_operator])
                except:
                    print("ALERT: error appending operator to list")

        elif drone_id_type_int == 2:
            faa_registration_id = drone_id_str
            #print("faa registration: " + str(faa_registration_id))
            # if a packet containing the FAA nunmber is recieved before the serial number, the operator ID
            # cannot be compared and normally results in an error that operator_id_position is undefined,
            # as it doesn't exist for this UA yet
            
            try: 
                
                operator_id_position = int(np.where(drone_data == latitude and drone_data == longitude)[0]) 
                try:
                    drone_data[operator_id_position,2] = faa_registration_id
                    operator_data[operator_id_position,2] = faa_registration_id
                except:
                    print("ALERT: New drone entry array not ready, wait for more packets")
            except:
                print("ALERT: Packets out of order, Operator does not exist for FAA Number:" + str(faa_registration_id))
        else:
            other_drone_id = drone_id_str

# PACKET DISSECTION SIFTING ______________________________________________________________
    if loop_in_ua_packet == 1:
    #main loop to pull drone data
        # Top of frame containing Drone and operator IDs and ID types
        if "ID Type:" in line:       #ADD ELIF AND IF TO 
            if "Operator ID Type:" in line: 
                operator_id_type_str = line.split("Operator ID Type: ")[1].rstrip('\n')
                operator_id_type_int = line 
            else:
                #Drone ID type 4 bit sequence starts after 12 spaces
                drone_id_type_str = line.split("ID Type: ")[1].rstrip('\n')
                drone_id_type_int = int(line[12:16], 2) #saves binary value as int
        elif "ID:" in line:
            if "Operator ID:" in line:
                operator_id_str = line.split("Operator ID: ")[1].rstrip('\n')
            else:
                drone_id_str = line.split("ID: ")[1].rstrip('\n')
        elif "UA Type:" in line:
            ua_type_str = line.split("UA Type: ")[1].rstrip('\n')
        elif "Operational Status:" in line:
            operational_status_str = line.split("Operational Status: ")[1].rstrip('\n')
        elif "Speed Multiplier:" in line:
            speed_multiplier_str = line.split("Speed Multiplier: ")[1].rstrip('\n')
        # Location Data
        elif "Direction:" in line:
            direction = int(line.split("Direction: ")[1].rstrip('\n'))
        elif "Speed:" in line:
            if "Vert Speed:" in line:
                vert_speed = int(line.split("Vert Speed: ")[1].rstrip('\n'))
            else:
                speed = int(line.split("Speed: ")[1].rstrip('\n'))   

        # lattitude and longitude are pulled as ints but are needed as floats where the first 
        elif "UA Latitude" in line:
            lat_temp = int(line.split("UA Latitude: ")[1].rstrip('\n'))
            lat_figs = 2 if lat_temp>0 else 3
            lat_length = len(str(lat_temp))
            latitude = lat_temp / (10 ** (lat_length - lat_figs))
        elif "UA Longitude:" in line:
            long_temp = int(line.split("UA Longitude: ")[1].rstrip('\n'))
            long_figs = 2 if long_temp>0 else 3
            long_length = len(str(long_temp))
            longitude = long_temp / (10 ** (long_length - long_figs))
        elif "UA Pressure Altitude:" in line:
            pressure_alt = int(line.split("Pressure Altitude: ")[1].rstrip('\n'))
        elif "UA Geodetic Altitude:" in line:
            geo_alt = int(line.split("Geodetic Altitude: ")[1].rstrip('\n'))
        elif "UA Height AGL:" in line:
            height_agl = int(line.split("Height AGL: ")[1].rstrip('\n')) - int(2000)
        
        # Operator Data
        elif contains_airborne == 1:
            if "Operator Location Type:" in line:
                op_loc_type = line.split("Operator Location Type: ")[1].rstrip('\n')
            elif "Operator Latitude" in line:
                op_lat_temp = int(line.split("Operator Latitude: ")[1].rstrip('\n'))
                op_lat_figs = 2 if op_lat_temp>0 else 3
                op_lat_length = len(str(op_lat_temp))
                op_latitude = op_lat_temp / (10 ** (op_lat_length - op_lat_figs))
            elif "Operator Longitude:" in line:
                op_long_temp = int(line.split("Operator Longitude: ")[1].rstrip('\n'))
                op_long_figs = 2 if op_long_temp>0 else 3
                op_long_length = len(str(op_long_temp))
                op_longitude = op_long_temp / (10 ** (op_long_length - op_long_figs))
            elif "Operator Geodetic Alt:" in line:
                op_geo_alt = int(line.split("Operator Geodetic Alt: ")[1].rstrip('\n'))
        elif contains_airborne == 0:
            op_loc_type = "unknown"
            op_latitude = "unknown"
            op_longitude = "unknown"
            op_geo_alt = "unknown"



# ADD IF BLOCK HERE TO REMOVE OLD ENTRIES--------------------------------------------------------------------- placed at end for speed

if remove_old_drones == 1:
    for j in range(1,len(drone_data)):   
        if drone_data[j,21] <= str(old_drone_num): 
            print("Drone no: " + str(j) + " was last updated in position " + str(drone_data[j,21]) + " making is OLD AS BONES MAINE")
            drone_data = np.delete(drone_data, (j), axis=0) 
            
# rotates drone and operator data so they can be displayed more easily
display_drone_data = np.fliplr(np.rot90(drone_data, -1))
display_operator_data = np.fliplr(np.rot90(operator_data, -1))
        
    
#opens csv in write mode and writes drone_data array to file
with open(drone_data_file_path, mode='w', newline='') as drone_data_file:
    writer = csv.writer(drone_data_file)
    writer.writerows(drone_data)
with open(operator_data_file_path, mode='w', newline='') as operator_data_file:
    writer = csv.writer(operator_data_file)
    writer.writerows(operator_data)
with open(display_data_file_path, mode ='w', newline='') as display_data_file:
    writer = csv.writer(display_data_file)
    writer.writerows(display_drone_data)
    writer.writerows(display_operator_data)

#end
