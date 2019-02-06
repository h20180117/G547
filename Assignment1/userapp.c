#include<stdio.h>
#include<stdlib.h>
#include<errno.h>
#include<fcntl.h>
#include<string.h>
#include<unistd.h>
#include<sys/types.h>
#include<stdint.h>


#define ACCL_X "/dev/adxl_x"
#define ACCL_Y "/dev/adxl_y"
#define ACCL_Z "/dev/adxl_z"


int main()
{
	unsigned int read_buf;
	int i,fd;
	char ch;
do 
{	
	printf("enter x for x-axis output, y for y-axis output, z for z-axis output, press e for exit\n");
	scanf(" %c",&ch);
	switch(ch)
   {
    	case 'x':
	fd = open(ACCL_X,O_RDWR);
        read(fd,&read_buf,sizeof(read_buf));
        printf("x-axis output =%u\n",read_buf);
        close(fd);
        break;
    	case 'y':
	fd = open(ACCL_Y,O_RDWR);
        read(fd,&read_buf,sizeof(read_buf));
        printf("y-axis output =%u\n",read_buf);
        close(fd);
        break;
    	case 'z':
	fd = open(ACCL_Z,O_RDWR);
        read(fd,&read_buf,sizeof(read_buf));
        printf("z-axis output =%u\n",read_buf);
        close(fd);
        break;
	case 'e':
	printf("Exit\n");
	break;
    	default:
        printf("invalid input\n");
        break;
   }
}while(ch!='e');

return 0;
}
