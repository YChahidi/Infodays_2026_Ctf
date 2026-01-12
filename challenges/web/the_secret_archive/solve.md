📖 Description
We've moved all our latest news to a digital archive. It's very basic, so there shouldn't be any bugs... right?

🕵️ Discovery
Analyze the Application: The "Site Archive Viewer" home page provides a link to view files: /view?file=news.txt.

Identify the Weakness: The app.py code uses send_file(filename) directly with the user-provided file parameter. There are no checks to see if the user is attempting to leave the current directory.

Local File Inclusion (LFI): Because the application is running in a Docker container with the flag at /etc/flag.txt, an attacker can try to navigate "up" the folder structure.

🛠️ Exploitation
Craft the Payload: Since the app runs in /home/ctfuser/, we need several levels of ../ to reach the root directory.

Execution: Use the following URL to bypass the intended directory: /view?file=../../../../etc/flag.txt

Result: The server processes the request and serves the contents of the flag file directly to the browser.

🏁 Flag
flag{infodays_traversal_master_2025}
