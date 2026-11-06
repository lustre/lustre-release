# This is fetched from the *server* for the session running on the client.
# Systems where the condition is TRUE run the test ("check || always_except").
# Systems where the condition evaluates to FALSE will except the test.
#
# facet op need_version             jira     space_separated_subtests
client  >= v2_16_58-22-ge342f475b9  LU-19325 17b
client  >= v2_17_50-150-g738222eaad LU-19836 26b
