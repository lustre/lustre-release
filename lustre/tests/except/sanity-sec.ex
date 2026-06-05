# This is fetched from the *server* for the session running on the client.
# Systems where the condition is TRUE run the test ("check || always_except").
# Systems where the condition evaluates to FALSE will except the test.
#
# facet op need_version             jira     space_separated_subtests
client  >= v2_16_57-13-g40cd140b85  LU-18357 27a 27b
