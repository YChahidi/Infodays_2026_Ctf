# 🏟️ Stadium Metadata Challenge

The challenge consists of downloading an image named `stadium.jpeg` from the provided website and finding a hidden flag inside it. When opening the image normally, nothing unusual is visible, which suggests that the flag is not hidden visually but rather stored in the file’s metadata.

After downloading the image, the next step is to analyze its metadata. Image files often contain additional information such as the author, software used, creation date, or artist name. To extract this information, we use the `exiftool` utility, which is commonly used in digital forensics and CTF challenges.

Once the file is available locally, we run ExifTool on it:

exiftool stadium.jpeg

This command outputs all metadata associated with the image. While reviewing the output, we notice a specific property named Artist. The value of this field contains the flag directly.

Artist                          : INFODAYS{ST4D1UM_V1P_4CC3SS}


