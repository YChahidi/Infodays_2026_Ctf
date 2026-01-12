Intro: Ping-o-Matic
Category: Web/Network | Difficulty: Easy | Points: 50

Challenge: The Agadir Stadium management has a tool to check if their servers are online. Can you use it to find something they didn't intend for you to see?

The Vulnerability: Command Injection. The tool takes an IP address and runs a ping command in the background without sanitizing the input.

The Solution:

Enter a standard IP, then use a semicolon (;) or pipe (|) to chain a second command.

Payload: 127.0.0.1; ls (to see the files) then 127.0.0.1; cat flag.txt.

Flag: flag{infodays_cmnd_inj3ction_succ3ss}
