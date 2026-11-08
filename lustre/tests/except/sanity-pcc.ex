# This is fetched from the *server* for the session running on the client.
# Systems where the condition is TRUE run the test ("check || always_except").
# Systems where the condition evaluates to FALSE will except the test.
#
# facet op need_version             jira     space_separated_subtests
client  >= v2_17_60-73              LU-20969 1a 1b 1c 1d 1e 1f 1g 2a 2b 2c
client  >= v2_17_60-73              LU-20969 3a 4 5 6 7a 7b 8 9 10a 10b 11 12
client  >= v2_17_60-73              LU-20969 13a 13b 13c 14 15 16 17 18 19 20
client  >= v2_17_60-73              LU-20969 21i 22 26 27 28 30 31 36a 101a
