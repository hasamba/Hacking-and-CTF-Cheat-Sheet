#!/bin/bash

clear
echo -e "\e[7;96m Which platform are you on? \e[0m"
echo -e 1. "\e[1;92m Hackthebox \e[0m"
echo -e 2. "\e[1;91m Tryhackme \e[0m"
echo -e 3. "\e[1;94m Vulnhub \e[0m"

read input

if [ $input = 1 ]
then
	platform=hackthebox
elif [ $input = 2 ]
then
	platform=tryhackme
elif [ $input = 3 ]
then
	platform=vulnhub
else
	echo Please put a valid number!
fi

echo
echo -e "\e[7;96m What is the name of the box? \e[0m"

read boxname


mkdir ~/Documents/labs/$platform/$boxname
cd ~/Documents/labs/$platform/$boxname

cp /home/hasamba/Documents/scripts/report.md .

echo 
echo -e "\e[7;96m what is the box IP? \e[0m"
read ip
echo $ip > ip.txt

mv report.md $platform-$boxname-$ip.md
subl $platform-$boxname-$ip.md
copyq show $boxname
copyq config clipboard_tab $boxname

#copy variables to clipboard to use with CopyQ
sleep 1
echo -n $platform | xclip -selection clipboard
sleep 1
echo -n $boxname | xclip -selection clipboard
sleep 1
echo -n $ip | xclip -selection clipboard
sleep 1 
echo -n cd ~/Documents/labs/$platform/$boxname | xclip -selection clipboard

echo
echo -e "\e[7;96m Would you like to start extra scripts & open web browser? \e[0m"
echo -e "1.\e[1;95m NmapAutomator \e[0m"
echo -e "2.\e[1;93m Legion Framework (Type 'Run' after load) \e[0m"
echo -e "3.\e[1;94m AutoRecon \e[0m"
echo -e "9.\e[1;90m Nothing \e[0m"

read input2

if [ $input2 = 1 ]
then
	clear
	firefox $ip
	nmapAutomator.sh $ip All
elif [ $input2 = 2 ]
then
	clear
	firefox $ip
	sudo ~/tools/legion/legion.py --host $ip --workdir ~/Documents/labs/$platform/$boxname/legion
elif [ $input2 = 3 ]
then
	clear
	autorecon $ip -o ~/Documents/labs/$platform/$boxname/autorecon -vv
fi
echo
echo -e "\e[7;96m New Folder is ready @: \e[0m"
pwd