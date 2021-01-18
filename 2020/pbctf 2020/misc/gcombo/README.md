Looking at the source of the google form, it essentially gives us a directed graph.
This was parsed and is present in parsed.py, solve.py uses breadth first search to find a path upto node 751651474.
The path generated from the script can be used on the google form which asks us for a password, which can be found in the source.
We can use the password `s3cuR3_p1n_id_2_3v3ry0ne` from the source, this will show us that flag is in the form `pbctf{<digits you got along the way>_<password>}`

So, the flag is: `pbctf{5812693370_s3cuR3_p1n_id_2_3v3ry0ne}`
