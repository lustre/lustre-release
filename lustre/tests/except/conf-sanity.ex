# This is fetched from the *server* for the session running on the client.
# Systems where the condition is TRUE run the test ("check || always_except").
# Systems where the condition evaluates to FALSE will except the test.
#
# facet op need_version             jira     space_separated_subtests
client  >= v2_15_65-31-g74a5b9efaa  LU-18348 32b 32c
client  >= v2_15_63-53-g1a6ef725c2  LU-16938 81
client  >= v2_16_55-19-gf69f27cc35  LU-17920 123ae 123ag
