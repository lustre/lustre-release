# This is fetched from the *server* for the session running on the client.
# Systems where the condition is TRUE run the test ("check || always_except").
# Systems where the condition evaluates to FALSE will except the test.
#
# facet op need_version             jira     space_separated_subtests
client  >  v2_16_54-54-ga2e3a2f5a3  LU-14590 0d
mds1    <  v2_14_55-100-g8a84c7f9c7 LU-14927 0f
client  >  v2_15_63-239-gab4ede45b4 LU-17856 56wa 56xe
mds1    <= CLIENT_VERSION           LU-18562 270a
client  >  v2_15_63-134-gdacc4b6d38 LU-15963 312
mds1    <= 2.16.61-1-g89cf292a8c2   LU-18938 360
