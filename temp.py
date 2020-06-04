import time
import datetime
timestamp = time.strftime("%d-%H")
filename = "".join(["temperaturedata", timestamp, ".log"])
datafile = open(filename, "a", 1)



count=1
tfile = open("/sys/devices/w1_bus_master1/28-01144a47feaa/w1_slave",'r')
text = tfile.read()
temperature_data = text.split()[-1]
temperature = float(temperature_data[2:])
temperature = temperature / 1000
datafile.write(time.strftime("%H-%M-%S  ")+str(temperature) + "\n")
count=count+1
time.sleep(1)
tfile.close()
datafile.close()
