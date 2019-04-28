# Script to display gyroscope data.
from time import sleep

def convert(x):
   if x>=128:
   x= x - 256
    return x

fd = open('/dev/gyro','r')
while(1):
    data = fd.read(3);
    foo = [ord(i) for i in data]
    foo = [convert(i) for i in foo]
    print (foo)
    sleep(0.5) 
