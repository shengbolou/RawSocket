# RawSocket in Python

http://www-edlab.cs.umass.edu/cs653/a3.html

implement HTTP, TCP, IP layer,

HTTP layer is easy, just a GET request, the header I use is simple:

GET {path} HTTP/1.0
Host: {hostname}

IP layer is also straightforward, just build the IP header with correct fields

TCP layer is the most complicated one, I have to implement checksum
function which calculates correct checksum and also a function to validate incoming packets checksum.

Map is used to store data with key=seq_num, at the end I sort by the key and get the final data in correct order.

