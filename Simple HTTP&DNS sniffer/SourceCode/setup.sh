#install modules libpcap
sudo apt-get install libpcap-dev

#compiling
gcc -o project project.c -lpcap -lm
