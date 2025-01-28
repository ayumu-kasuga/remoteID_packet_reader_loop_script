"""
packet_reader_script.py
Captstone Team 10 2024-2025

Opens a CSV file which contains a cache of drone data. 

Reads PCAP files exported in wireshark as test files by looping through the entie files until
it reachs a line that contains a droneID, if this is an old droneID it filters through the rest 
of the data contained in the packets and inserts them in the appropiate row, if the droneID is
new is increments and adds the drone in a blank column

drone_data = [
    ['Drone No / session name'],#local name / differintiator
    ['Serial Number'], #string, ANSI/CTA-2063-A idType = 1
    ['CAA Assigned Number'], #string, CAA Assigned Registration ID
    ['UA type'], #string, UA type, Aeroplane (0) -> other (15) 
    ['Operator ID'], #string
    ['Affiliation'],# to be decided as department become involved
    ['Operational Status'], #string, status Undecared (0) -> Remote ID System Failure
    ['Speed Multiplier'], #string
    ['Direction'], #int
    ['Speed'],#int
    ['Vert Speed'],#int
    ['Lattitude'], #confirm protocol for single digit
    ['Longitude'], #confirm protocol for single digit
    ['Pressure Altitude'], #int
    ['Geodetic Altitude'], #int
    ['Height AGL'] , #int
    ['Horizontal Accuracy'],#string
    ['Vertical Accuracy'],#string
    ['Baro Accuracy'], #string
    ['Speed Accuracy'], #string
    ['Time'],]   #double or string
"""
# ADD NAME ABILITY
# FIX LUA FILE AND REMOVE REPEATED MISPELLED LATITUDE
# TEST BETTER EDGE DETECTION FOR PACKET

#importing requirements
import csv
from array import *

drone_data_file_path = 'drone_array.csv'
white_list_file_path = 'white_list.csv'
#opens drone data and white list csv files as arrays.
with open(drone_data_file_path, mode='r', newline='') as drone_data_file:
    drone_data = list(csv.reader(drone_data_file))
with open(white_list_file_path, mode='r', newline='') as white_list_file:
    white_list = list(csv.reader(white_list_file))

#open / read pcap text file
pcap_file_path = 'pcap_sample_noisy.txt'
pcap_file = open(pcap_file_path, 'r').readlines()

#for loop runs through text file
for line in pcap_file:

# PACKET READING COMPONENT________________________________________________________________
# the elif statements below generate strings for ID types, Operational status
# speed multiplier, and accuracy values.
# It generates integers for location data like lattitude, logitude, speed, and altitude 
# line.split, saves only the value after the colon,
# .rstrip removes the next line character \n

# Top of frame containing Drone and operator IDs and ID types
    if "ID Type:" in line:
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
    elif "Lattitude:"in line:
        latitude = int(line.split("Lattitude: ")[1].rstrip('\n'))
    elif "Latitude" in line: #REPEATED DUE TO MISSPELLING IN LUA FILE, REMOVE WHEN FIXED
        latitude = int(line.split("Latitude: ")[1].rstrip('\n'))
    elif "Longitude:" in line:
        longitude = int(line.split("Longitude: ")[1].rstrip('\n'))
    elif "Pressure Altitude:" in line:
        pressure_alt = int(line.split("Pressure Altitude: ")[1].rstrip('\n'))
    elif "Geodetic Altitude:" in line:
        geo_alt = int(line.split("Geodetic Altitude: ")[1].rstrip('\n'))
    elif "Height AGL:" in line:
        height_agl = int(line.split("Height AGL: ")[1].rstrip('\n'))
# Accuracy Strings
    elif "Horizontal Accuracy:" in line:
        hori_accuracy_str = line.split("Horizontal Accuracy: <")[1].rstrip('\n')
    elif "Vertical Accuracy:" in line:
        vert_accuracy_str = line.split("Vertical Accuracy: <")[1].rstrip('\n')
    elif "Baro Accuracy:" in line:
        baro_accuracy_str = line.split("Baro Accuracy: <")[1].rstrip('\n')
    elif "Speed Accuracy:" in line:
        speed_accuracy_str = line.split("Speed Accuracy: <")[1].rstrip('\n')
    elif "Broadcast" and "OPENDRONEID" in line:
        packet_time_stamp = float(line[8:22])


# PACKET EDGE, this could also use a packet line counter___________________________________
# this may need to be changed, so far last row in packet
    elif "Timestamp Accuracy" in line: #TIME STAMP ACCURACY IS GOOD, "OPENDRONEID" MAY BE BETTER, TEST THIS

        #print block
        """print("Operator ID Type:" + operator_id_type_str)
        print("ID Type:" + drone_id_type_str)
        print("ID Type:" + str(drone_id_type_int))
        print("Operator ID:" + operator_id_str)
        print("ID:" + drone_id_str)
        print("UA Type: " + ua_type_str)
        print("Operational Status: " + operational_status_str)
        print("Speed Multiplier:" + speed_multiplier_str)
        print("Direction: " + str(direction))
        print("Vert Speed:" + str(vert_speed))
        print("Speed:" + str(speed))
        print("Latitude:" + str(latitude))
        print("Latitude:" + str(latitude))
        print("Longitude:" + str(longitude))
        print("Pressure Altitude:" + str(pressure_alt))
        print("Geodetic Altitude:" + str(geo_alt))
        print("Height AGL:" + str(height_agl))
        print("Horizontal Accuracy: <" + hori_accuracy_str)
        print("Vertical Accuracy: <" + vert_accuracy_str)
        print("Baro Accuracy: <" + baro_accuracy_str)
        print("Speed Accuracy: <" + speed_accuracy_str)
        print("\nTime Stamp:" + str(packet_time_stamp))
        print("Drone Listed Name: + drone_name)"""

#ARRAY FILLING ALGORITHM____________________________________________________________________________
        if drone_id_type_int == 1: #(Serial number transmitted)
            serial_number = drone_id_str #sets detected ID as serial number

            if serial_number in white_list[1]:      #checks whilelist for serial number
                white_list_entry_position = white_list[1].index(serial_number) 
                affiliation = white_list[0][white_list_entry_position]
                drone_name = white_list[2][white_list_entry_position]
                if affiliation == "":               #serial number inlist wiothout affiliation
                    affiliation = "unspecified"
            else:
                affiliation = "unknown"             # no serial number in list

            if serial_number in drone_data[1]:      #check if serial number exists in array
                serial_number_position = drone_data[1].index(serial_number) 
                #finds position of serial number in array and overwrites existing entry at location
                try:
                    drone_data[1][serial_number_position] = serial_number
                    drone_data[3][serial_number_position] = ua_type_str               # UA type
                    drone_data[4][serial_number_position] = operator_id_str           # Operator ID
                    drone_data[5][serial_number_position] = affiliation               # Affiliation
                    drone_data[6][serial_number_position] = operational_status_str    # Operational Status
                    drone_data[7][serial_number_position] = speed_multiplier_str      # Speed Multiplier
                    drone_data[8][serial_number_position] = direction                 # Direction
                    drone_data[9][serial_number_position] = speed                     # Speed
                    drone_data[10][serial_number_position] = vert_speed               # Vert Speed
                    drone_data[11][serial_number_position] = latitude                 # Latitude
                    drone_data[12][serial_number_position] = longitude                # Longitude
                    drone_data[13][serial_number_position] = pressure_alt             # Pressure Altitude
                    drone_data[14][serial_number_position] = geo_alt                  # Geodetic Altitude
                    drone_data[15][serial_number_position] = height_agl               # Height AGL
                    drone_data[16][serial_number_position] = hori_accuracy_str        # Horizontal Accuracy
                    drone_data[17][serial_number_position] = vert_accuracy_str        # Vertical Accuracy
                    drone_data[18][serial_number_position] = baro_accuracy_str        # Baro Accuracy
                    drone_data[19][serial_number_position] = speed_accuracy_str       # Speed Accuracy
                    drone_data[20][serial_number_position] = packet_time_stamp        # Time
                    drone_data[21][serial_number_position] = drone_name               # Name from list
                except:
                    print(str(drone_data_file_path) + " filled incorrectly, empty all columns excpet column 0")
            else:
                # appends array by adding a column with new serial number
                try:
                    drone_data[1].append(serial_number)             # Serial Number
                    drone_data[3].append(ua_type_str)               # UA type
                    drone_data[4].append(operator_id_str)           # Operator ID
                    drone_data[5].append(affiliation)               # Affiliation
                    drone_data[6].append(operational_status_str)    # Operational Status
                    drone_data[7].append(speed_multiplier_str)      # Speed Multiplier
                    drone_data[8].append(direction)                 # Direction
                    drone_data[9].append(speed)                     # Speed
                    drone_data[10].append(vert_speed)               # Vert Speed
                    drone_data[11].append(latitude)                 # Latitude
                    drone_data[12].append(longitude)                # Longitude
                    drone_data[13].append(pressure_alt)             # Pressure Altitude
                    drone_data[14].append(geo_alt)                  # Geodetic Altitude
                    drone_data[15].append(height_agl)               # Height AGL
                    drone_data[16].append(hori_accuracy_str)        # Horizontal Accuracy
                    drone_data[17].append(vert_accuracy_str)        # Vertical Accuracy
                    drone_data[18].append(baro_accuracy_str)        # Baro Accuracy
                    drone_data[19].append(speed_accuracy_str)       # Speed Accuracy
                    drone_data[20].append(packet_time_stamp)        # Time
                    drone_data[21].append(drone_name)               # Name from list
                except:
                    print(str(drone_data_file_path) + " row 0 filled incorrectly, empty all columns excpet column 0")
        
        elif drone_id_type_int == 2:
            try:
                operator_id_position = drone_data[4].index(operator_id_str)
            except:
                print("Incomplete packet, Operator does not exist")
            faa_registration_id = drone_id_str

            if faa_registration_id in drone_data[2]: #checks if faa registration exists in array
                drone_data[2][operator_id_position] = faa_registration_id
            else:    
                drone_data[2].append(faa_registration_id)       
        else:
            other_drone_id = drone_id_str


#opens csv in write mode and writes drone_data array to file
with open(drone_data_file_path, mode='w', newline='') as drone_data_file:
    writer = csv.writer(drone_data_file)
    writer.writerows(drone_data)

    #prints array here
    for i in range(len(drone_data)):
        print(drone_data[i])
#pcap_file.close()
#end